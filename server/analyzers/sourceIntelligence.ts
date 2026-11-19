import * as cheerio from 'cheerio';
import type {
  BackgroundDataCollectionItem,
  CheckFinding,
  DiscoveredSubdomainInfo,
  ExternalDataTransmissionItem,
  FormSecurityDetail,
  SourceIntelligenceData,
  SupplyChainResourceSummary,
  SuspiciousCodeSignal,
} from '../types.ts';
import { detectCompoundBrandLookalike } from './brandIntelligence.ts';
import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';

export interface ExternalSourceAssetsInput {
  fetchedScripts?: { url: string; code: string }[];
  fetchedCss?: { url: string; css: string }[];
}

function classifySubdomainRole(host: string): DiscoveredSubdomainInfo['role'] {
  const lower = host.toLowerCase();
  if (/(?:^|\.)(?:auth|login|signin|sso|oauth|accounts?|id|verify|secure)\b/.test(lower)) return 'auth';
  if (/(?:^|\.)(?:api|graphql|gateway|ws|rpc|rest|backend)\b/.test(lower)) return 'api';
  if (/(?:^|\.)(?:cdn|static|assets|media|img|images|fonts|js|css|files|dl)\b/.test(lower)) return 'cdn_static';
  if (/(?:^|\.)(?:mail|smtp|imap|mx|webmail|newsletter)\b/.test(lower)) return 'mail';
  if (/(?:^|\.)(?:admin|panel|dashboard|cpanel|manage|internal|console)\b/.test(lower)) return 'admin';
  return 'general';
}

const KNOWN_CDN_DOMAINS = new Set([
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'ajax.googleapis.com',
  'code.jquery.com',
  'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com',
  'cdn.tailwindcss.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
]);

const KNOWN_TRACKERS = [
  { name: 'Google Analytics / GTM', pattern: /googletagmanager\.com|google-analytics\.com|ga\.js|gtag/i },
  { name: 'Meta Pixel', pattern: /connect\.facebook\.net|fbevents\.js/i },
  { name: 'Hotjar', pattern: /hotjar\.com/i },
  { name: 'Mixpanel', pattern: /mixpanel\.com/i },
  { name: 'Sentry', pattern: /sentry\.io|browser\.sentry-cdn\.com/i },
  { name: 'Cloudflare Insights', pattern: /static\.cloudflareinsights\.com/i },
];

const VULNERABLE_LIB_PATTERNS = [
  { library: 'jQuery', pattern: /jquery[.-](\d+\.\d+\.\d+)/i, maxSafe: '3.5.0', advisory: 'jQuery <3.5.0 is vulnerable to XSS in HTML parsing.' },
  { library: 'Bootstrap JS', pattern: /bootstrap[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.3.1', advisory: 'Bootstrap <4.3.1 has XSS vulnerabilities in tooltip/popover data attributes.' },
  { library: 'AngularJS', pattern: /angular[.-](\d+\.\d+\.\d+)/i, maxSafe: '1.8.0', advisory: 'AngularJS 1.x has multiple prototype pollution and template injection vectors.' },
  { library: 'Lodash', pattern: /lodash[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.17.21', advisory: 'Lodash <4.17.21 is vulnerable to prototype pollution and regular expression denial of service.' },
];

function decodeJsObfuscatedExpression(
  expr: string,
  varMap: Map<string, { value: string; obfuscated: boolean; from: string }>
): { value: string; obfuscated: boolean; decodedFrom?: string } | null {
  const trimmed = expr.trim().replace(/;$/, '');
  if (!trimmed) return null;

  // 1. Variable lookup
  if (/^[A-Za-z_$][A-Za-z0-9_$]{0,40}$/.test(trimmed)) {
    const resolved = varMap.get(trimmed);
    if (resolved) return { value: resolved.value, obfuscated: resolved.obfuscated, decodedFrom: resolved.from };
    return null;
  }

  // 2. atob('...')
  const atobMatch = trimmed.match(/^atob\s*\(\s*(['"`])([A-Za-z0-9+/=_-]{8,})\1\s*\)$/i);
  if (atobMatch) {
    try {
      const normalized = atobMatch[2].replace(/-/g, '+').replace(/_/g, '/');
      const decoded = Buffer.from(normalized, 'base64').toString('utf8').trim();
      if (/^https?:\/\/|^wss?:\/\/|^\/[A-Za-z0-9/_-]+/i.test(decoded)) {
        return { value: decoded, obfuscated: true, decodedFrom: `atob("${atobMatch[2].slice(0, 32)}...")` };
      }
    } catch {
      return null;
    }
  }

  // 3. decodeURIComponent('...') / unescape('...')
  const decodeUriMatch = trimmed.match(/^(?:decodeURIComponent|unescape)\s*\(\s*(['"`])([^'"`]+)\1\s*\)$/i);
  if (decodeUriMatch) {
    try {
      const decoded = decodeURIComponent(decodeUriMatch[2]).trim();
      if (/^https?:\/\/|^wss?:\/\/|^\/[A-Za-z0-9/_-]+/i.test(decoded)) {
        return { value: decoded, obfuscated: true, decodedFrom: 'decodeURIComponent(...)' };
      }
    } catch {
      return null;
    }
  }

  // 4. String.fromCharCode(...)
  const charCodeMatch = trimmed.match(/^String\.fromCharCode\s*\(\s*([0-9,\s]{10,300})\s*\)$/i);
  if (charCodeMatch) {
    const nums = charCodeMatch[1].split(',').map((n) => Number(n.trim())).filter((n) => Number.isFinite(n) && n >= 32 && n <= 126);
    if (nums.length >= 8) {
      const decoded = String.fromCharCode(...nums).trim();
      if (/^https?:\/\/|^wss?:\/\//i.test(decoded)) {
        return { value: decoded, obfuscated: true, decodedFrom: 'String.fromCharCode(...)' };
      }
    }
  }

  // 5. Concatenated string literals: 'https://' + 'evil.com' + '/collect'
  if (/^(['"`][^'"`]+['"`]\s*\+\s*)+['"`][^'"`]+['"`]$/.test(trimmed)) {
    const parts = Array.from(trimmed.matchAll(/(['"`])([^'"`]+)\1/g)).map((m) => m[2]);
    const joined = parts.join('').trim();
    if (/^https?:\/\/|^wss?:\/\/|^\/[A-Za-z0-9/_-]+/i.test(joined)) {
      return { value: joined, obfuscated: true, decodedFrom: 'String concatenation' };
    }
  }

  // 6. Plain or \xHH / \uHHHH escaped string literal
  const litMatch = trimmed.match(/^(['"`])([^'"`]{2,260})\1$/);
  if (litMatch) {
    let val = litMatch[2];
    const hasEscapes = /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/.test(val);
    if (hasEscapes) {
      val = val
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    }
    val = val.trim();
    if (/^https?:\/\/|^wss?:\/\/|^\/\/[A-Za-z0-9.-]+|^\/[A-Za-z0-9_./?=&-]+/i.test(val)) {
      return { value: val, obfuscated: hasEscapes, decodedFrom: hasEscapes ? 'Hex/Unicode escape string' : undefined };
    }
  }

  return null;
}

function analyzeJsBackgroundCollection(jsCode: string): BackgroundDataCollectionItem[] {
  const items: BackgroundDataCollectionItem[] = [];
  if (!jsCode.trim()) return items;

  const detectedTriggers: string[] = [];
  if (/\b(?:DOMContentLoaded|onload|window\.onload)\b/i.test(jsCode)) detectedTriggers.push('on page load');
  if (/\bsetInterval\s*\(/i.test(jsCode)) detectedTriggers.push('setInterval (periodic polling)');
  if (/\bsetTimeout\s*\(/i.test(jsCode)) detectedTriggers.push('setTimeout (delayed trigger)');
  if (/\b(?:beforeunload|pagehide|visibilitychange)\b/i.test(jsCode)) detectedTriggers.push('page exit / hidden');
  if (/addEventListener\s*\(\s*['"](?:keydown|keyup|keypress|input|change)['"]/i.test(jsCode)) detectedTriggers.push('input / keystroke listener');
  if (/addEventListener\s*\(\s*['"]submit['"]/i.test(jsCode)) detectedTriggers.push('form submit');

  const extractSnippet = (re: RegExp): string => {
    const m = jsCode.match(re);
    if (!m || m.index === undefined) return '';
    const start = Math.max(0, m.index - 24);
    const end = Math.min(jsCode.length, m.index + m[0].length + 65);
    return jsCode.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 140);
  };

  // 1. Cookies & Browser Storage
  const storageApis: string[] = [];
  if (/document\.cookie\b/i.test(jsCode)) storageApis.push('document.cookie');
  if (/\blocalStorage\.(?:getItem|key|length|setItem)|Object\.(?:keys|entries)\s*\(\s*localStorage/i.test(jsCode)) storageApis.push('localStorage');
  if (/\bsessionStorage\.(?:getItem|key|length|setItem)|Object\.(?:keys|entries)\s*\(\s*sessionStorage/i.test(jsCode)) storageApis.push('sessionStorage');
  if (/indexedDB\.open\s*\(/i.test(jsCode)) storageApis.push('indexedDB');

  if (storageApis.length > 0) {
    items.push({
      id: 'bg-cookies-storage',
      category: 'cookies_storage',
      title: { en: 'Cookies & Local Storage Harvesting', ar: 'جمع ملفات تعريف الارتباط والتخزين المحلي للمتصفح' },
      apisUsed: storageApis,
      triggers: detectedTriggers.length > 0 ? detectedTriggers.slice(0, 3) : ['script execution'],
      excerpt: extractSnippet(/document\.cookie|localStorage\.\w+|sessionStorage\.\w+|indexedDB\.open/) || storageApis.join(', '),
      riskLevel: storageApis.includes('document.cookie') ? 'high' : 'medium',
      detail: {
        en: `JavaScript reads browser state via ${storageApis.join(', ')} (session tokens, auth cookies, or persisted user data).`,
        ar: `يقرأ كود JavaScript بيانات الجلسة والتخزين في المتصفح عبر (${storageApis.join('، ')}) مثل الكوكيز ورموز الجلسة.`,
      },
    });
  }

  // 2. Credential / Form / DOM Input Scraping
  const inputApis: string[] = [];
  if (/input\s*\[\s*type\s*=\s*['"]?password['"]?\s*\]|getElementById\s*\(\s*['"][^'"]*pass[^'"]*['"]/i.test(jsCode)) inputApis.push('password DOM selector');
  if (/querySelectorAll\s*\(\s*['"][^'"]*(?:input|form|textarea)[^'"]*['"]\s*\)|new\s+FormData\s*\(/i.test(jsCode)) inputApis.push('FormData / querySelectorAll(input)');
  if (/\.(?:value|elements)\b[\s\S]{0,80}(?:email|card|cvv|otp|token|pin|secret)/i.test(jsCode)) inputApis.push('sensitive field value reader');

  if (inputApis.length > 0) {
    items.push({
      id: 'bg-credential-inputs',
      category: 'credentials_inputs',
      title: { en: 'Silent Form & Credential Field Collection', ar: 'التقاط مدخلات النماذج وحقول كلمات المرور بالخلفية' },
      apisUsed: inputApis,
      triggers: detectedTriggers.length > 0 ? detectedTriggers.slice(0, 3) : ['DOM read'],
      excerpt: extractSnippet(/input\s*\[\s*type\s*=\s*['"]?password|new\s+FormData|querySelectorAll\s*\(\s*['"][^'"]*input/) || inputApis.join(', '),
      riskLevel: inputApis.includes('password DOM selector') ? 'high' : 'medium',
      detail: {
        en: `Scripts extract form inputs or password/PII values directly from the DOM (${inputApis.join(', ')}).`,
        ar: `يقوم السكربت بقراءة حقول الإدخال أو كلمات المرور مباشرة من DOM عبر (${inputApis.join('، ')}).`,
      },
    });
  }

  // 3. Keystrokes & Clipboard Spying
  const keyClipApis: string[] = [];
  if (/addEventListener\s*\(\s*['"](?:keydown|keyup|keypress|input)['"]/i.test(jsCode)) keyClipApis.push('keyboard/input event listener');
  if (/navigator\.clipboard\.readText|addEventListener\s*\(\s*['"](?:paste|copy)['"]/i.test(jsCode)) keyClipApis.push('clipboard read/paste listener');
  if (keyClipApis.length > 0) {
    items.push({
      id: 'bg-keystrokes-clipboard',
      category: 'keystrokes_clipboard',
      title: { en: 'Keystroke & Clipboard Activity Monitoring', ar: 'مراقبة ضغطات المفاتيح أو قراءة الحافظة بالخلفية' },
      apisUsed: keyClipApis,
      triggers: ['real-time user typing / paste'],
      excerpt: extractSnippet(/addEventListener\s*\(\s*['"](?:keydown|keyup|keypress|input|paste|copy)['"]|navigator\.clipboard\.readText/),
      riskLevel: 'high',
      detail: {
        en: `Listeners hook ${keyClipApis.join(', ')} to capture typed characters or pasted clipboard contents silently.`,
        ar: `تلتقط مستمعات الأحداث (${keyClipApis.join('، ')}) ما يكتبه المستخدم أو يلصقه في الحافظة بشكل خفي.`,
      },
    });
  }

  // 4. Browser / Hardware Fingerprinting
  const fpApis: string[] = [];
  if (/\.toDataURL\s*\(|getImageData\s*\(/.test(jsCode) && /canvas|createElement\s*\(\s*['"]canvas['"]/i.test(jsCode)) fpApis.push('Canvas fingerprint (toDataURL)');
  if (/WEBGL_debug_renderer_info|getParameter\s*\([^)]*(?:RENDERER|VENDOR)|getContext\s*\(\s*['"](?:webgl|experimental-webgl)['"]/i.test(jsCode)) fpApis.push('WebGL GPU fingerprint');
  if (/(?:Offline)?AudioContext\b[\s\S]{0,160}(?:createOscillator|createDynamicsCompressor|destination)/i.test(jsCode)) fpApis.push('AudioContext fingerprint');
  const navPropsCount = [
    /navigator\.userAgent/i.test(jsCode),
    /navigator\.platform/i.test(jsCode),
    /navigator\.hardwareConcurrency/i.test(jsCode),
    /navigator\.deviceMemory/i.test(jsCode),
    /navigator\.languages?/i.test(jsCode),
    /screen\.(?:width|height|colorDepth)/i.test(jsCode),
    /Intl\.DateTimeFormat\s*\(\)\s*\.resolvedOptions\s*\(\)\.timeZone/i.test(jsCode),
    /navigator\.plugins/i.test(jsCode),
  ].filter(Boolean).length;
  if (navPropsCount >= 3) fpApis.push(`System/Navigator profile (${navPropsCount} hardware/screen traits)`);

  if (fpApis.length > 0) {
    items.push({
      id: 'bg-browser-fingerprinting',
      category: 'browser_fingerprinting',
      title: { en: 'Silent Device & Browser Fingerprinting', ar: 'جمع البصمة الرقمية للجهاز والمتصفح بالخلفية' },
      apisUsed: fpApis,
      triggers: detectedTriggers.length > 0 ? detectedTriggers.slice(0, 3) : ['silent initialization'],
      excerpt: extractSnippet(/toDataURL|WEBGL_debug_renderer_info|AudioContext|hardwareConcurrency|deviceMemory|resolvedOptions\(\)\.timeZone/),
      riskLevel: fpApis.length >= 2 ? 'high' : 'medium',
      detail: {
        en: `Collects unique hardware, GPU, screen, timezone, or canvas telemetry (${fpApis.join(', ')}) to track or profile visitors silently.`,
        ar: `يجمع السكربت بصمة فريدة للجهاز وبطاقة الرسوميات والشاشة والمنطقة الزمنية (${fpApis.join('، ')}) لتتبع الزائر في الخلفية.`,
      },
    });
  }

  // 5. WebRTC Local IP / Battery / Network Telemetry
  const netDevApis: string[] = [];
  if (/new\s+(?:webkit|moz)?RTCPeerConnection\s*\(/i.test(jsCode)) netDevApis.push('WebRTC IP/ICE probing');
  if (/navigator\.getBattery\s*\(/i.test(jsCode)) netDevApis.push('Battery API');
  if (/navigator\.connection\b/i.test(jsCode)) netDevApis.push('NetworkInformation API');
  if (/navigator\.geolocation\.(?:getCurrentPosition|watchPosition)/i.test(jsCode)) netDevApis.push('Geolocation API');
  if (netDevApis.length > 0) {
    items.push({
      id: 'bg-device-network',
      category: 'device_network_webrtc',
      title: { en: 'Device, Network & WebRTC Probing', ar: 'جمع بيانات الشبكة والموقع أو WebRTC IP بالخلفية' },
      apisUsed: netDevApis,
      triggers: detectedTriggers.length > 0 ? detectedTriggers.slice(0, 3) : ['background probe'],
      excerpt: extractSnippet(/RTCPeerConnection|getBattery|navigator\.connection|geolocation\.getCurrentPosition/),
      riskLevel: netDevApis.includes('WebRTC IP/ICE probing') ? 'high' : 'medium',
      detail: {
        en: `Scripts query network/IP or hardware status via ${netDevApis.join(', ')}.`,
        ar: `يفحص الكود عنوان الشبكة أو حالة الجهاز أو الموقع عبر (${netDevApis.join('، ')}).`,
      },
    });
  }

  // 6. Silent Periodic / Exit Polling
  if (
    (/\bsetInterval\s*\(/i.test(jsCode) || /\b(?:beforeunload|pagehide|visibilitychange)\b/i.test(jsCode)) &&
    (/\bfetch\s*\(|sendBeacon|XMLHttpRequest|WebSocket/i.test(jsCode))
  ) {
    items.push({
      id: 'bg-background-polling',
      category: 'background_polling',
      title: { en: 'Periodic / On-Exit Background Transmission Loop', ar: 'دورة جمع وإرسال دوري أو عند مغادرة الصفحة بالخلفية' },
      apisUsed: [
        /\bsetInterval\s*\(/i.test(jsCode) ? 'setInterval' : '',
        /\b(?:beforeunload|pagehide|visibilitychange)\b/i.test(jsCode) ? 'visibilitychange / unload hook' : '',
      ].filter(Boolean),
      triggers: ['timer / page hide'],
      excerpt: extractSnippet(/setInterval\s*\(|addEventListener\s*\(\s*['"](?:beforeunload|pagehide|visibilitychange)['"]/),
      riskLevel: 'medium',
      detail: {
        en: 'Runs a background timer or exit hook paired with network transmission calls.',
        ar: 'يشغّل مؤقتاً دورياً أو مستمع مغادرة الصفحة مرتبطاً باستدعاءات إرسال بيانات للشبكة.',
      },
    });
  }

  return items;
}

function analyzeExternalTransmissions(
  jsCode: string,
  finalUrl: string,
  finalHost: string,
  finalRegDomain: string,
  hasBgCollection: boolean,
  crossOriginFormActions: string[]
): ExternalDataTransmissionItem[] {
  const results: ExternalDataTransmissionItem[] = [];
  const seenKeys = new Set<string>();

  // Build simple variable string table for resolving const/let/var ep = atob(...) or '...'
  const varMap = new Map<string, { value: string; obfuscated: boolean; from: string }>();
  const varRegex = /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,40})\s*=\s*([^;\n]{4,260})/g;
  let vm: RegExpExecArray | null;
  let varCount = 0;
  while ((vm = varRegex.exec(jsCode)) !== null && varCount < 60) {
    varCount++;
    const varName = vm[1];
    const resolved = decodeJsObfuscatedExpression(vm[2], varMap);
    if (resolved) {
      varMap.set(varName, {
        value: resolved.value,
        obfuscated: resolved.obfuscated,
        from: resolved.decodedFrom || 'variable assignment',
      });
    }
  }

  const recordEndpoint = (
    rawExpr: string,
    method: ExternalDataTransmissionItem['method'],
    excerpt: string
  ) => {
    const resolved = decodeJsObfuscatedExpression(rawExpr, varMap);
    if (!resolved) return;
    let resolvedUrl: URL;
    try {
      const candidate = resolved.value.startsWith('//') ? `https:${resolved.value}` : resolved.value;
      resolvedUrl = new URL(candidate, finalUrl);
    } catch {
      return;
    }
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(resolvedUrl.protocol)) return;

    const destUrlStr = resolvedUrl.toString().slice(0, 180);
    const destHost = resolvedUrl.hostname.toLowerCase();
    const destReg = extractRegistrableDomain(destHost);
    const isThirdParty = destReg !== finalRegDomain;
    const dedupKey = `${method}|${destUrlStr}`;
    if (seenKeys.has(dedupKey)) return;
    seenKeys.add(dedupKey);

    const rel = classifyDomainRelationship(finalHost, destHost);
    const lookalike = !lookupDomainOwnership(destHost).matched ? detectCompoundBrandLookalike(destHost, destReg) : null;
    const relationshipStatus: ExternalDataTransmissionItem['relationshipStatus'] = !isThirdParty || rel.isSameOrganization
      ? 'same_organization'
      : lookalike
        ? 'suspicious_lookalike'
        : rel.isBenignOrAuthorized
          ? 'authorized_provider'
          : 'external_unknown';

    results.push({
      destinationUrl: destUrlStr,
      destinationHost: destHost,
      method,
      obfuscatedUrl: resolved.obfuscated,
      decodedFrom: resolved.decodedFrom,
      isThirdParty,
      relationshipStatus,
      pairedWithBackgroundCollection: hasBgCollection,
      excerpt: excerpt.replace(/\s+/g, ' ').trim().slice(0, 150),
      detail: isThirdParty
        ? relationshipStatus === 'authorized_provider'
          ? {
              en: `Transmits telemetry via ${method} to recognized third-party provider (${destHost}).`,
              ar: `يرسل بيانات عبر ${method} إلى مزود خدمة طرف ثالث معروف (${destHost}).`,
            }
          : {
              en: `Transmits data via ${method} to external unverified host (${destHost})${resolved.obfuscated ? ` [URL obfuscated via ${resolved.decodedFrom}]` : ''}.`,
              ar: `يرسل بيانات عبر ${method} إلى خادم خارجي غير مرتبط بالموقع (${destHost})${resolved.obfuscated ? ` [الرابط كان مموهاً عبر ${resolved.decodedFrom}]` : ''}.`,
            }
        : {
            en: `Sends request via ${method} to same-origin/organization endpoint (${destHost}).`,
            ar: `يرسل طلباً عبر ${method} إلى نفس النطاق أو المؤسسة (${destHost}).`,
          },
    });
  };

  // Patterns: fetch(arg), xhr.open(method, arg), sendBeacon(arg), new WebSocket(arg), new EventSource(arg), .src = arg
  const callPatterns: { regex: RegExp; method: ExternalDataTransmissionItem['method']; argGroup: number }[] = [
    { regex: /\bfetch\s*\(\s*([^,)\n]{2,200})/g, method: 'fetch', argGroup: 1 },
    { regex: /\.open\s*\(\s*['"][A-Za-z]+['"]\s*,\s*([^,)\n]{2,200})/g, method: 'xhr', argGroup: 1 },
    { regex: /navigator\.sendBeacon\s*\(\s*([^,)\n]{2,200})/g, method: 'sendBeacon', argGroup: 1 },
    { regex: /new\s+WebSocket\s*\(\s*([^,)\n]{2,200})/g, method: 'websocket', argGroup: 1 },
    { regex: /new\s+EventSource\s*\(\s*([^,)\n]{2,200})/g, method: 'eventsource', argGroup: 1 },
    { regex: /(?:\b(?:img|image|beacon|pixel|script|iframe|s|i)|new\s+Image\s*\(\s*\))\s*\.src\s*=\s*([^;\n]{2,200})/gi, method: 'dynamic_beacon', argGroup: 1 },
  ];

  for (const cp of callPatterns) {
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = cp.regex.exec(jsCode)) !== null && count < 30 && results.length < 25) {
      count++;
      recordEndpoint(m[cp.argGroup], cp.method, m[0]);
    }
  }

  for (const formTarget of crossOriginFormActions) {
    recordEndpoint(`"${formTarget}"`, 'form_action', `<form action="${formTarget}">`);
  }

  return results;
}

export function analyzeSourceIntelligence(
  finalUrl: string,
  headers: Record<string, string>,
  htmlBuffer?: Buffer,
  externalAssets?: ExternalSourceAssetsInput
): {
  sourceIntel: SourceIntelligenceData;
  formDetails: FormSecurityDetail[];
  supplyChain: SupplyChainResourceSummary;
  findings: CheckFinding[];
} {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];

  const parsedUrl = new URL(finalUrl);
  const finalHost = parsedUrl.hostname.toLowerCase();
  const finalRegDomain = extractRegistrableDomain(finalHost);

  const securityHeaders = {
    csp: headers['content-security-policy'],
    hsts: headers['strict-transport-security'],
    xFrameOptions: headers['x-frame-options'],
    xContentTypeOptions: headers['x-content-type-options'],
    referrerPolicy: headers['referrer-policy'],
    permissionsPolicy: headers['permissions-policy'],
  };

  if (!htmlBuffer) {
    const emptySource: SourceIntelligenceData = {
      ogTags: {},
      jsonLdCount: 0,
      jsonLdTypes: [],
      baseTagHijack: false,
      securityHeaders,
      externalJsFiles: [],
      externalCssFiles: [],
      inlineJsCount: 0,
      inlineCssCount: 0,
      iframeSources: [],
      embeddedResources: [],
      hiddenInputs: [],
      suspiciousAttributes: [],
      suspiciousCodeSignals: [],
      lureExcerpts: [],
      externalCssUrls: [],
      cssExternalDomains: [],
      storageAndCookieAccess: [],
      formExfiltrationHooks: [],
      isMinifiedBundlePresent: false,
      titleContentMismatch: false,
    };
    const emptySupplyChain: SupplyChainResourceSummary = {
      totalExternalDomains: 0,
      scripts: [],
      stylesheets: [],
      iframes: [],
      fonts: [],
      imagesCount: 0,
      externalImagesCount: 0,
      apiEndpoints: [],
      trackingServices: [],
      cdnDomains: [],
      externalForms: [],
      outdatedLibraries: [],
    };
    return { sourceIntel: emptySource, formDetails: [], supplyChain: emptySupplyChain, findings };
  }

  const html = htmlBuffer.toString('utf8');
  const $ = cheerio.load(html);

  // 1. Meta Tags & Canonical
  const canonicalUrl = $('link[rel="canonical"]').attr('href')?.trim();
  const ogTags: Record<string, string> = {};
  $('meta[property^="og:"], meta[name^="og:"]').each((_, el) => {
    const prop = ($(el).attr('property') || $(el).attr('name') || '').trim();
    const content = ($(el).attr('content') || '').trim();
    if (prop) ogTags[prop] = content;
  });

  const jsonLdTypes: string[] = [];
  let jsonLdCount = 0;
  $('script[type="application/ld+json"]').each((_, el) => {
    jsonLdCount++;
    try {
      const parsed = JSON.parse($(el).html() || '{}');
      if (parsed['@type']) {
        const t = Array.isArray(parsed['@type']) ? parsed['@type'].join(', ') : String(parsed['@type']);
        jsonLdTypes.push(t);
      }
    } catch {
      // ignore
    }
  });

  // 2. Base Tag Hijacking (ignore benign same-company/authorized domains)
  const baseTagHref = $('base').attr('href')?.trim();
  let baseTagHijack = false;
  if (baseTagHref) {
    try {
      const resolvedBase = new URL(baseTagHref, finalUrl);
      const baseReg = extractRegistrableDomain(resolvedBase.hostname);
      const rel = classifyDomainRelationship(finalHost, resolvedBase.hostname);
      if (baseReg !== finalRegDomain && !rel.isBenignOrAuthorized) {
        baseTagHijack = true;
      }
    } catch {
      baseTagHijack = true;
    }
  }

  const metaRefresh = $('meta[http-equiv="refresh" i]').attr('content')?.trim();

  // 3. External & Inline Resources
  const externalJsFiles: string[] = [];
  const externalCssFiles: string[] = [];
  let inlineJsCount = 0;
  let inlineCssCount = 0;
  const iframeSources: string[] = [];
  const embeddedResources: { tag: string; src: string }[] = [];
  const externalDomainsSet = new Set<string>();

  const scriptList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const stylesheetList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const iframeList: { url: string; host: string; isThirdParty: boolean }[] = [];
  const fontList: string[] = [];
  const apiEndpointsSet = new Set<string>();
  const subdomainMap = new Map<string, Set<string>>();

  const recordSubdomainCandidate = (rawUrlOrHost: string | undefined, sourceTag: string) => {
    if (!rawUrlOrHost) return;
    try {
      const resolved = /^https?:\/\//i.test(rawUrlOrHost)
        ? new URL(rawUrlOrHost)
        : new URL(rawUrlOrHost, finalUrl);
      const h = resolved.hostname.toLowerCase().replace(/\.$/, '');
      if (!h || h === finalHost) return;
      if (extractRegistrableDomain(h) === finalRegDomain) {
        if (!subdomainMap.has(h)) subdomainMap.set(h, new Set());
        if (subdomainMap.size <= 35) subdomainMap.get(h)!.add(sourceTag);
      }
    } catch {
      // ignore invalid URL
    }
  };

  if (canonicalUrl) recordSubdomainCandidate(canonicalUrl, 'canonical');
  if (ogTags['og:url']) recordSubdomainCandidate(ogTags['og:url'], 'og:url');
  if (baseTagHref) recordSubdomainCandidate(baseTagHref, 'base');

  const brandLookalikeLinks: NonNullable<SourceIntelligenceData['brandLookalikeLinks']> = [];
  const seenLookalikeHosts = new Set<string>();
  const checkLookalikeTarget = (rawUrl: string) => {
    if (!rawUrl || !/^https?:\/\//i.test(rawUrl)) return;
    try {
      const u = new URL(rawUrl);
      const host = u.hostname.toLowerCase();
      const reg = extractRegistrableDomain(host);
      if (reg === finalRegDomain || seenLookalikeHosts.has(host)) return;
      if (lookupDomainOwnership(host).matched) return;
      const compound = detectCompoundBrandLookalike(host, reg);
      if (compound) {
        seenLookalikeHosts.add(host);
        brandLookalikeLinks.push({
          url: u.toString().slice(0, 160),
          host,
          targetBrand: compound.brand,
          officialDomain: compound.officialDomain,
          evidence: compound.evidence,
        });
      }
    } catch {
      // ignore invalid URL
    }
  };

  $('a[href]').each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (href && !href.startsWith('#') && !/^javascript:/i.test(href)) {
      recordSubdomainCandidate(href, 'anchor');
      checkLookalikeTarget(href);
    }
  });
  $('form[action]').each((_, el) => {
    const act = ($(el).attr('action') || '').trim();
    if (act) {
      recordSubdomainCandidate(act, 'form');
      checkLookalikeTarget(act);
    }
  });
  $('img[src], source[src], video[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) recordSubdomainCandidate(src, 'media');
  });

  $('script[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) {
      externalJsFiles.push(src.slice(0, 160));
      recordSubdomainCandidate(src, 'script');
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host) || KNOWN_CDN_DOMAINS.has(reg);
        if (isTP) externalDomainsSet.add(host);
        scriptList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  $('script:not([src])').each((_, el) => {
    inlineJsCount++;
    const code = $(el).html() || '';
    // Extract static API endpoints & subdomains from JS code strings
    const urlMatches = code.match(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,20}(?:\/[^\s"'<>]+)?/gi) || [];
    for (const m of urlMatches) {
      if (apiEndpointsSet.size < 20) apiEndpointsSet.add(m.slice(0, 120));
      recordSubdomainCandidate(m, 'inline_js');
    }
  });

  $('link[rel="stylesheet"]').each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (href) {
      externalCssFiles.push(href.slice(0, 160));
      recordSubdomainCandidate(href, 'stylesheet');
      try {
        const u = new URL(href, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host);
        if (isTP) externalDomainsSet.add(host);
        stylesheetList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  const externalCssUrls: string[] = [];
  const cssExternalDomainsSet = new Set<string>();
  const extractCssUrls = (cssText: string) => {
    const cssRegex = /(?:@import\s+(?:url\()?['"]?([^'")\s]+)|url\(\s*['"]?(https?:\/\/[^'")\s]+)['"]?\s*\))/gi;
    let m: RegExpExecArray | null;
    while ((m = cssRegex.exec(cssText)) !== null) {
      const rawUrl = (m[1] || m[2] || '').trim();
      if (!rawUrl || /^data:/i.test(rawUrl)) continue;
      if (externalCssUrls.length < 30) externalCssUrls.push(rawUrl.slice(0, 160));
      recordSubdomainCandidate(rawUrl, 'css');
      try {
        const u = new URL(rawUrl, finalUrl);
        const h = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(h);
        if (reg !== finalRegDomain) {
          cssExternalDomainsSet.add(h);
          externalDomainsSet.add(h);
        }
      } catch {
        // ignore invalid css url
      }
    }
  };

  $('style').each((_, el) => {
    inlineCssCount++;
    extractCssUrls($(el).html() || '');
  });
  $('[style]').each((_, el) => {
    const st = $(el).attr('style') || '';
    if (/url\(/i.test(st)) extractCssUrls(st);
  });
  for (const extCss of externalAssets?.fetchedCss || []) {
    extractCssUrls(extCss.css.slice(0, 80000));
  }

  let hiddenOverlayIframes = 0;
  $('iframe[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    const st = ($(el).attr('style') || '').toLowerCase();
    if (/opacity\s*:\s*0\b|left\s*:\s*-\d{3,}|top\s*:\s*-\d{3,}|visibility\s*:\s*hidden/.test(st)) {
      hiddenOverlayIframes++;
    }
    if (src) {
      iframeSources.push(src.slice(0, 160));
      recordSubdomainCandidate(src, 'iframe');
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const isTP = extractRegistrableDomain(host) !== finalRegDomain;
        iframeList.push({ url: u.toString(), host, isThirdParty: isTP });
      } catch {
        // ignore
      }
    }
  });

  $('[data-font], link[rel*="font"], @import').each((_, el) => {
    const href = $(el).attr('href') || $(el).attr('src') || '';
    if (/fonts\./i.test(href) || /\.woff2?/i.test(href)) {
      fontList.push(href.slice(0, 100));
    }
  });

  $('object, embed, svg').each((_, el) => {
    const src = $(el).attr('data') || $(el).attr('src') || '';
    embeddedResources.push({ tag: el.tagName.toLowerCase(), src: src.slice(0, 120) });
  });

  let imagesCount = 0;
  let externalImagesCount = 0;
  $('img[src]').each((_, el) => {
    imagesCount++;
    const src = ($(el).attr('src') || '').trim();
    if (/^https?:\/\//i.test(src)) {
      try {
        if (extractRegistrableDomain(new URL(src).hostname) !== finalRegDomain) {
          externalImagesCount++;
        }
      } catch {
        // ignore
      }
    }
  });

  // 4. Hidden Inputs & Suspicious Attributes
  const hiddenInputs: { name?: string; type: string; valuePreview?: string }[] = [];
  $('input[type="hidden"]').each((_, el) => {
    const name = $(el).attr('name') || $(el).attr('id');
    const val = $(el).attr('value') || '';
    hiddenInputs.push({ name, type: 'hidden', valuePreview: val.slice(0, 40) });
  });

  const suspiciousAttributes: { attribute: string; tag: string; snippet: string }[] = [];
  $('*').each((_, el) => {
    const node = el as any;
    const tag = (node.tagName || 'element').toLowerCase();
    for (const attr of node.attribs ? Object.keys(node.attribs) : []) {
      const val = node.attribs[attr] || '';
      if (
        /^on[a-z]+/i.test(attr) ||
        /javascript:|data:text\/html/i.test(val) ||
        (attr === 'formaction' && /^https?:\/\//i.test(val))
      ) {
        suspiciousAttributes.push({ attribute: attr, tag, snippet: `${attr}="${val.slice(0, 60)}"` });
      }
    }
  });

  // 5. Context-Aware Static JS Code Signals (inline + safely retrieved external scripts)
  const suspiciousCodeSignals: SuspiciousCodeSignal[] = [];
  const fullHtmlText = html.slice(0, 120000);
  const inlineOnlyJs = $('script:not([src])')
    .map((_, el) => $(el).html() || '')
    .get()
    .join('\n');
  const externalScriptsCode = (externalAssets?.fetchedScripts || [])
    .map((s) => `/* ext:${s.url} */\n${s.code}`)
    .join('\n');
  const externalJsInspectedCount = (externalAssets?.fetchedScripts || []).length;
  const inlineJsConcat = `${inlineOnlyJs}\n${externalScriptsCode}`.slice(0, 150000);

  const storageAndCookieAccess: string[] = [];
  if (/document\.cookie\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('document.cookie');
  if (/\blocalStorage\.(?:getItem|setItem|removeItem|clear)\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('localStorage');
  if (/\bsessionStorage\.(?:getItem|setItem|removeItem|clear)\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('sessionStorage');

  const formExfiltrationHooks: string[] = [];
  const hasSubmitListener = /addEventListener\s*\(\s*['"]submit['"]|onsubmit\s*=/i.test(inlineJsConcat);
  const hasNetworkExfil = /\bfetch\s*\(|new\s+XMLHttpRequest\b|navigator\.sendBeacon\s*\(/i.test(inlineJsConcat);
  if (hasSubmitListener && hasNetworkExfil) {
    formExfiltrationHooks.push('Form submit listener combined with asynchronous network transmission (fetch/XHR/sendBeacon)');
  }
  if (/addEventListener\s*\(\s*['"](?:keydown|keyup|input|paste)['"][\s\S]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)/i.test(inlineJsConcat)) {
    formExfiltrationHooks.push('Keystroke/input listener paired with remote HTTP transmission');
  }
  if (storageAndCookieAccess.includes('document.cookie') && hasNetworkExfil) {
    formExfiltrationHooks.push('Cookie access (document.cookie) co-occurs with asynchronous network transmission');
  }

  // Static Post-Load DOM Mutation & Client-Rendered Content Divergence Detection (without executing JS!)
  const jsDomMutationPayloads: string[] = [];
  if (
    /(?:\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write)\s*(?:=|\()[\s\S]{0,300}(?:<form|<input[^>]+password|<iframe)/i.test(
      inlineJsConcat
    )
  ) {
    jsDomMutationPayloads.push('JS dynamically injects <form>, <input type="password">, or <iframe> into DOM after page load');
  }
  if (
    /(?:\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write)\s*(?:=|\()\s*[^;\n]{0,120}\batob\s*\(/i.test(
      inlineJsConcat
    )
  ) {
    jsDomMutationPayloads.push('JS decodes Base64 payload directly into live DOM markup via innerHTML / document.write');
  }
  if (
    /(?:document\.createElement\s*\(\s*['"](?:form|iframe)['"]\s*\)|createElement\s*\(\s*['"]input['"]\s*\)[\s\S]{0,220}password)/i.test(
      inlineJsConcat
    )
  ) {
    jsDomMutationPayloads.push('JS programmatically constructs credential form or iframe elements post-load');
  }
  if (
    /setTimeout\s*\([\s\S]{0,220}(?:location(?:\.href)?\s*=|location\.replace|innerHTML\s*=)/i.test(inlineJsConcat)
  ) {
    jsDomMutationPayloads.push('Delayed timer (setTimeout) alters page DOM or triggers post-load redirect');
  }

  // Minified vs Malicious Obfuscation Classification:
  // Long compressed lines (webpack/vite bundles) WITHOUT _0x arrays or encoded eval() are standard minified code!
  const lines = inlineJsConcat.split('\n');
  const hasLongMinifiedLine = lines.some((l) => l.length > 450 && /\bfunction\b|\bconst\b|\breturn\b|=>/.test(l));
  const hasMaliciousObfuscationMarker =
    /_0x[0-9a-f]{4,}/i.test(inlineJsConcat) ||
    /eval\s*\(\s*(?:atob|unescape|decodeURIComponent|function\s*\(\s*p\s*,\s*a\s*,\s*c)/i.test(inlineJsConcat) ||
    /String\.fromCharCode\s*\([^)]{25,}\)/i.test(inlineJsConcat);
  const isMinifiedBundlePresent = Boolean(
    hasLongMinifiedLine || externalJsFiles.some((s) => /\.min\.js|bundle|chunk|vendor/i.test(s))
  );
  const obfuscationVsMinifiedNote = isMinifiedBundlePresent && !hasMaliciousObfuscationMarker
    ? {
        en: 'Detected minified/compressed JavaScript bundle without malicious obfuscation markers (_0x hex arrays or encoded eval payloads). Minified production bundles are normal and NOT treated as malicious.',
        ar: 'تم رصد أكواد JavaScript مضغوطة (Minified) دون علامات تمويه خبيث؛ ضغط الأكواد الإنتاجية أمر طبيعي ولا يُصنف كبرمجية ضارة.',
      }
    : undefined;

  if (/\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-eval',
      indicator: 'Encoded eval() execution',
      category: 'dynamic_eval',
      codeExcerpt: 'eval(atob/unescape/...) detected in script blocks',
      contextAssessment: {
        en: 'eval() directly executes decoded payloads at runtime, a pattern commonly used to mask malicious injections.',
        ar: 'يُستخدم eval() لتنفيذ حمولات مفكوكة الشفرة ديناميكياً، وهو نمط شائع لإخفاء الأكواد الخبيثة.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  } else if (/\beval\s*\(/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-eval',
      indicator: 'eval() usage',
      category: 'dynamic_eval',
      codeExcerpt: 'eval(...) detected in inline script',
      contextAssessment: {
        en: 'Standard eval() call present; evaluate alongside form behavior and domain identity before inferring risk.',
        ar: 'استدعاء eval() موجود في السكربت؛ يتم تقييمه ضمن السياق العام والنماذج ولا يكفي بمفرده للحكم بالخطر.',
      },
      benignContextPossible: true,
      riskLevel: 'low',
    });
  }

  if (/atob\s*\(|btoa\s*\(/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-base64',
      indicator: 'Base64 string decoding (atob)',
      category: 'obfuscation',
      codeExcerpt: 'atob() / btoa() encoding functions present',
      contextAssessment: {
        en: 'Base64 functions decode strings at runtime. Common in web apps for client-side state, but also used by phishing kits to conceal exfiltration URLs.',
        ar: 'تفك شفرة Base64 النصوص أثناء التشغيل؛ شائعة في التطبيقات الحديثة ولكنها تُستخدم أيضاً لإخفاء روابط الإرسال في التصيد.',
      },
      benignContextPossible: true,
      riskLevel: 'low',
    });
  }

  if (/document\.write\s*\(/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-docwrite',
      indicator: 'document.write() injection',
      category: 'dom_injection',
      codeExcerpt: 'document.write(...) used in script',
      contextAssessment: {
        en: 'document.write() overwrites DOM content during page load. Legacy scripts use this, while obfuscated variants inject rogue UI.',
        ar: 'يستطيع document.write كتابة محتوى في الصفحة مباشرة أثناء التحميل.',
      },
      benignContextPossible: true,
      riskLevel: 'low',
    });
  }

  // Advanced Static JS Behavioral Forensics:
  const obfuscationMarkerMatches = inlineJsConcat.match(/_0x[0-9a-f]{4,}/gi) || [];
  if (hasMaliciousObfuscationMarker && !suspiciousCodeSignals.some((s) => s.id === 'js-obfuscation')) {
    suspiciousCodeSignals.push({
      id: 'js-obfuscation',
      indicator: 'Obfuscated identifier array / decoder packer',
      category: 'obfuscation',
      codeExcerpt: `Malicious obfuscation marker(s) detected (${obfuscationMarkerMatches.length || 1})`,
      contextAssessment: {
        en: 'Script contains _0x hex lookup arrays or CharCode packers strongly associated with phishing kits and payload concealment.',
        ar: 'يحتوي الكود على مصفوفات تعتيم برمجي أو فك تشفير نصوص تُستخدم غالباً لإخفاء أدوات التصيد.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  const dynamicFormActionRewrite =
    /(?:\b\w*form\w*|\bdocument\.forms\[[^\]]+\]|querySelector\s*\([^)]*form[^)]*\))\.action\s*=|\.[a-z0-9_$]*action\s*=\s*['"`]https?:\/\/|\.action\s*=\s*['"`](?:https?:)?\/\/|setAttribute\s*\(\s*['"]action['"]/i.test(
      inlineJsConcat
    );
  if (dynamicFormActionRewrite) {
    formExfiltrationHooks.push('Script dynamically rewrites <form action> submission target');
    suspiciousCodeSignals.push({
      id: 'js-form-action-rewrite',
      indicator: 'Dynamic form.action target rewriting',
      category: 'exfiltration',
      codeExcerpt: 'Inline JS dynamically alters form.action or setAttribute("action", ...)',
      contextAssessment: {
        en: 'JavaScript modifies the form destination endpoint at runtime, a technique used by credential skimmers to redirect form submissions.',
        ar: 'يُعيد الجافاسكربت توجيه وجهة إرسال النموذج ديناميكياً أثناء التشغيل، وهو أسلوب شائع في سرقة بيانات الدخول.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  const passwordFieldDomHooks =
    /input\s*\[\s*type\s*=\s*['"]?password['"]?\s*\]|getElementById\s*\(\s*['"][^'"]*pass[^'"]*['"]\s*\)/i.test(
      inlineJsConcat
    ) && hasNetworkExfil;
  if (passwordFieldDomHooks) {
    formExfiltrationHooks.push('Password field DOM access paired with background network exfiltration (fetch/XHR/sendBeacon)');
    suspiciousCodeSignals.push({
      id: 'js-password-exfil-hook',
      indicator: 'DOM password reader + background transmission',
      category: 'exfiltration',
      codeExcerpt: 'Password element selector paired with fetch / XHR / sendBeacon',
      contextAssessment: {
        en: 'Inline script reads password field values directly from the DOM alongside asynchronous HTTP transmission calls.',
        ar: 'يقرأ السكربت قيمة حقل كلمة المرور مع وجود استدعاءات إرسال شبكة في الخلفية.',
      },
      benignContextPossible: true,
      riskLevel: 'high',
    });
  }

  const walletDrainerPattern =
    /navigator\.clipboard\.writeText[\s\S]{0,220}(?:0x[a-fA-F0-9]{16,40}|bc1[a-z0-9]{10,})|(?:0x[a-fA-F0-9]{40}|eth_sendTransaction)[\s\S]{0,220}navigator\.clipboard\.writeText/i.test(
      inlineJsConcat
    );
  if (walletDrainerPattern) {
    suspiciousCodeSignals.push({
      id: 'js-wallet-clipboard-hijack',
      indicator: 'Clipboard address / crypto drainer pattern',
      category: 'clipboard',
      codeExcerpt: 'Wallet/address constant paired with navigator.clipboard.writeText',
      contextAssessment: {
        en: 'Pattern swaps copied addresses or triggers wallet transaction scripting automatically.',
        ar: 'نمط يشتبه في استبدال عنوان المحفظة في الحافظة تلقائياً أو تمرير معاملات احتيالية.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  const hasPasswordOnPage = $('input[type="password"]').length > 0;
  const antiDebugTraps =
    hasPasswordOnPage &&
    (/\bdebugger\s*;/i.test(inlineJsConcat) ||
      (/oncontextmenu\s*=\s*.*return\s+false/i.test(inlineJsConcat) && /F12|ctrlKey\s*&&\s*shiftKey/i.test(inlineJsConcat)));
  if (antiDebugTraps) {
    suspiciousCodeSignals.push({
      id: 'js-anti-debug',
      indicator: 'Anti-inspection / debugger trap on credential page',
      category: 'dom_injection',
      codeExcerpt: 'DevTools inspection block or debugger trap alongside password field',
      contextAssessment: {
        en: 'Phishing kits block right-click and DevTools debugging to hinder analyst inspection of credential forms.',
        ar: 'تُعطّل صفحة تحتوي حقول كلمات مرور أدوات الفحص واختصارات المطور لإعاقة تحليل السورس.',
      },
      benignContextPossible: false,
      riskLevel: 'medium',
    });
  }

  // Title vs Actual Content Contradiction Detection
  const titleText = $('title').first().text().trim().toLowerCase();
  const cloneDoc = cheerio.load(fullHtmlText);
  cloneDoc('script, style, noscript').remove();
  const bodyPlain = cloneDoc('body').text().replace(/\s+/g, ' ').trim().toLowerCase();
  let titleContentMismatch = false;
  let titleMismatchDetail: { en: string; ar: string } | undefined;
  const authoritativeBrandsInTitle = ['google', 'microsoft', 'paypal', 'apple', 'facebook', 'instagram', 'amazon', 'netflix', 'github'].filter((b) =>
    titleText.includes(b) && !finalRegDomain.includes(b)
  );
  if (authoritativeBrandsInTitle.length > 0 && !bodyPlain.includes(authoritativeBrandsInTitle[0]) && bodyPlain.length > 40) {
    titleContentMismatch = true;
    titleMismatchDetail = {
      en: `Page <title> references "${authoritativeBrandsInTitle[0]}" while visible body text diverges from that identity.`,
      ar: `عنوان الصفحة (<title>) يذكر "${authoritativeBrandsInTitle[0]}" بينما يختلف المحتوى المرئي الفعلي عن هذه الهوية.`,
    };
  } else if (titleText.length > 5 && /(login|sign in|security|verification)/i.test(titleText) && /(airdrop|claim prize|you won|virus infected|out[- ]of[- ]date)/i.test(bodyPlain)) {
    titleContentMismatch = true;
    titleMismatchDetail = {
      en: 'Page <title> presents a security/login header while visible body content promotes deceptive alerts or prize scams.',
      ar: 'يظهر <title> كصفحة دخول أو أمان بينما يعرض المحتوى الفعلي تنبيهات مزيفة أو عروضاً احتيالية.',
    };
  }

  // 6. Detailed Per-Form Analysis (FormSecurityDetail[])
  const formDetails: FormSecurityDetail[] = [];
  $('form').each((idx, el) => {
    const action = ($(el).attr('action') || '').trim();
    const method = ($(el).attr('method') || 'GET').toUpperCase();
    const idOrName = $(el).attr('id') || $(el).attr('name');
    let resolvedHost = finalHost;
    let isCrossOrigin = false;
    let originMismatch = false;

    if (action) {
      try {
        const u = new URL(action, finalUrl);
        resolvedHost = u.hostname.toLowerCase();
        const rel = classifyDomainRelationship(finalHost, resolvedHost);
        isCrossOrigin = extractRegistrableDomain(resolvedHost) !== finalRegDomain && !rel.isBenignOrAuthorized;
        originMismatch = isCrossOrigin;
      } catch {
        // relative action
      }
    }

    const inputTypesSet = new Set<string>();
    let pwdCount = 0;
    let emailCount = 0;
    let otpCount = 0;
    let pinCount = 0;
    let cardCount = 0;
    let hiddenCount = 0;
    let invisibleCount = 0;
    const unusualAttrs: string[] = [];
    const jsHandlers: string[] = [];

    $(el)
      .find('input, select, textarea')
      .each((_, inputEl) => {
        const t = ($(inputEl).attr('type') || 'text').toLowerCase();
        inputTypesSet.add(t);
        const nameId = ($(inputEl).attr('name') || $(inputEl).attr('id') || '').toLowerCase();
        const style = ($(inputEl).attr('style') || '').toLowerCase();

        if (t === 'hidden') {
          hiddenCount++;
        } else if (t === 'password') {
          pwdCount++;
        } else if (t === 'email' || /(?:^|[^a-z])(email|user|login)(?:$|[^a-z])/.test(nameId)) {
          emailCount++;
        } else if (/(?:^|[^a-z])(otp|2fa|pin[-_ ]?code)(?:$|[^a-z])/.test(nameId)) {
          otpCount++;
        } else if (/(?:^|[^a-z])(card[-_ ]?num|cvv|cvc|ccnum)(?:$|[^a-z])/.test(nameId)) {
          cardCount++;
        }

        if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b/.test(style)) {
          invisibleCount++;
        }

        for (const attr of inputEl.attribs ? Object.keys(inputEl.attribs) : []) {
          if (/^on[a-z]+/i.test(attr)) jsHandlers.push(attr);
        }
      });

    let formRisk: FormSecurityDetail['riskLevel'] = 'informational';
    const reasonEn: string[] = [];
    const reasonAr: string[] = [];

    if (isCrossOrigin && pwdCount > 0) {
      formRisk = 'critical';
      reasonEn.push('Password form submits to an external cross-origin domain.');
      reasonAr.push('نموذج كلمة المرور يرسل البيانات إلى نطاق خارجي مختلف.');
    } else if (pwdCount > 0 && !action) {
      formRisk = formExfiltrationHooks.length > 0 && /Keystroke/i.test(formExfiltrationHooks.join(' ')) ? 'high' : 'informational';
      reasonEn.push('Password form handles submission via client script / SPA state (no HTML action attribute). Verify exact domain identity.');
      reasonAr.push('يتعامل نموذج كلمة المرور مع الإرسال عبر السكربت المحلي (SPA) بدون وسم action؛ تحقق من هوية النطاق.');
    } else if (pwdCount > 0) {
      formRisk = 'informational';
      reasonEn.push('Standard same-origin password authentication form.');
      reasonAr.push('نموذج تسجيل دخول قياسي يرسل البيانات لنفس النطاق.');
    }

    formDetails.push({
      pageUrl: finalUrl,
      formIndex: idx + 1,
      idOrName,
      action: action || '[empty / current page]',
      resolvedActionHost: resolvedHost,
      method,
      usesHttps: finalUrl.startsWith('https://'),
      isCrossOrigin,
      originMismatch,
      inputTypes: Array.from(inputTypesSet),
      passwordCount: pwdCount,
      emailCount,
      otpCount,
      pinCount,
      cardCount,
      hiddenCount,
      invisibleCount,
      unusualAttributes: unusualAttrs,
      jsHandlers,
      riskLevel: formRisk,
      reason: {
        en: reasonEn.join(' ') || 'Standard form structure.',
        ar: reasonAr.join(' ') || 'بنية نموذج قياسية.',
      },
    });
  });

  // 7. Supply Chain Analysis & Outdated Libraries
  const trackingServices: { name: string; host: string }[] = [];
  for (const trk of KNOWN_TRACKERS) {
    for (const sc of scriptList) {
      if (trk.pattern.test(sc.url)) {
        if (!trackingServices.some((t) => t.name === trk.name)) {
          trackingServices.push({ name: trk.name, host: sc.host });
        }
      }
    }
  }

  const cdnDomains = Array.from(externalDomainsSet).filter((d) => KNOWN_CDN_DOMAINS.has(d));
  const outdatedLibraries: { library: string; detectedVersion: string; sourceUrl: string; advisory: string }[] = [];

  for (const sc of scriptList) {
    for (const libDef of VULNERABLE_LIB_PATTERNS) {
      const match = sc.url.match(libDef.pattern);
      if (match?.[1]) {
        outdatedLibraries.push({
          library: libDef.library,
          detectedVersion: match[1],
          sourceUrl: sc.url,
          advisory: libDef.advisory,
        });
      }
    }
  }

  const supplyChain: SupplyChainResourceSummary = {
    totalExternalDomains: externalDomainsSet.size,
    scripts: scriptList,
    stylesheets: stylesheetList,
    iframes: iframeList,
    fonts: fontList,
    imagesCount,
    externalImagesCount,
    apiEndpoints: Array.from(apiEndpointsSet),
    trackingServices,
    cdnDomains,
    externalForms: formDetails.filter((f) => f.isCrossOrigin).map((f) => f.action),
    outdatedLibraries,
  };

  const discoveredSubdomains: DiscoveredSubdomainInfo[] = Array.from(subdomainMap.entries()).map(([host, srcSet]) => {
    const role = classifySubdomainRole(host);
    const hasRiskyContext = (hasPasswordOnPage || formDetails.some((f) => f.isCrossOrigin)) && (role === 'auth' || role === 'admin');
    return {
      host,
      sources: Array.from(srcSet),
      role,
      suspiciousRole: hasRiskyContext,
    };
  });

  const bodyWordCount = bodyPlain ? bodyPlain.split(' ').length : 0;
  const hasSpaMountRoot = Boolean(
    $('#root, #app, #__next, #__nuxt, app-root').length > 0 || $('noscript').text().toLowerCase().includes('javascript')
  );
  const dynamicContentAfterJsLikely = Boolean(
    jsDomMutationPayloads.length > 0 || (hasSpaMountRoot && bodyWordCount < 35 && (inlineJsCount > 0 || externalJsFiles.length > 0))
  );

  const staticVsRenderedNote = dynamicContentAfterJsLikely
    ? jsDomMutationPayloads.length > 0
      ? {
          en: `Level A Static Analysis detected client-side JS scripts designed to inject/replace DOM content or redirect after initial load (${jsDomMutationPayloads[0]}). Level B isolated browser execution is not active locally; findings are based on inspected static source payloads.`,
          ar: `رصد التحليل الساكن (المستوى A) سكربتات JavaScript تُغيّر محتوى DOM أو تُعيد التوجيه بعد التحميل الأولي (${jsDomMutationPayloads[0]}). بيئة المتصفح المعزولة (المستوى B) غير متاحة محلياً؛ لذا تستند النتائج لقراءة السورس الفعلي.`,
        }
      : {
          en: 'Page serves a thin client-rendered JavaScript shell (SPA mount root with minimal static HTML text). Full post-render DOM requires an isolated headless browser (Level B, currently inactive); Level A inspected static HTML and accessible scripts only.',
          ar: 'تعتمد الصفحة على تطبيق JavaScript يُنشئ المحتوى بعد التحميل (SPA). قراءة شجرة DOM النهائية بعد التشغيل تتطلب متصفحاً معزولاً (المستوى B غير مفعّل محلياً)، وقد جرى فحص HTML والسكربتات المتاحة ساكنياً عبر المستوى A.',
        }
    : undefined;

  if (jsDomMutationPayloads.length > 0 && !suspiciousCodeSignals.some((s) => s.id === 'js-dom-mutation')) {
    const injectsSensitiveDom = jsDomMutationPayloads.some((m) => /<form|password|<iframe|atob/i.test(m));
    suspiciousCodeSignals.push({
      id: 'js-dom-mutation',
      indicator: 'Post-load JS DOM mutation / hidden markup injection',
      category: 'dom_injection',
      codeExcerpt: jsDomMutationPayloads[0],
      contextAssessment: {
        en: injectsSensitiveDom
          ? 'Inline/fetched JS constructs forms, password inputs, or decoded HTML fragments dynamically after page load—a classic cloaking technique to bypass static scanners.'
          : 'Script modifies DOM nodes or redirects asynchronously after a timer.',
        ar: injectsSensitiveDom
          ? 'يحقن الجافاسكربت نماذج إدخال أو حقول كلمة مرور أو شيفرة HTML مفكوكة بعد تحميل الصفحة؛ وهو أسلوب إخفاء لتفادي فحص HTML الساكن.'
          : 'يُعدّل السكربت عناصر الصفحة أو يوجهها بعد مؤقت زمني.',
      },
      benignContextPossible: !injectsSensitiveDom,
      riskLevel: injectsSensitiveDom ? 'high' : 'low',
    });
  }

  const backgroundDataCollection = analyzeJsBackgroundCollection(inlineJsConcat);
  const crossOriginActionsForTx = formDetails.filter((f) => f.isCrossOrigin).map((f) => f.action);
  const externalDataTransmissions = analyzeExternalTransmissions(
    inlineJsConcat,
    finalUrl,
    finalHost,
    finalRegDomain,
    backgroundDataCollection.length > 0,
    crossOriginActionsForTx
  );

  for (const tx of externalDataTransmissions) {
    if (tx.isThirdParty && apiEndpointsSet.size < 25) {
      apiEndpointsSet.add(tx.destinationUrl.slice(0, 120));
    }
  }

  const sourceIntel: SourceIntelligenceData = {
    canonicalUrl,
    ogTags,
    jsonLdCount,
    jsonLdTypes,
    baseTagHref,
    baseTagHijack,
    metaRefresh,
    securityHeaders,
    externalJsFiles,
    externalCssFiles,
    inlineJsCount,
    inlineCssCount,
    iframeSources,
    embeddedResources,
    hiddenInputs,
    suspiciousAttributes,
    suspiciousCodeSignals,
    lureExcerpts: [],
    externalCssUrls,
    cssExternalDomains: Array.from(cssExternalDomainsSet),
    storageAndCookieAccess,
    formExfiltrationHooks,
    isMinifiedBundlePresent,
    obfuscationVsMinifiedNote,
    titleContentMismatch,
    titleMismatchDetail,
    discoveredSubdomains,
    brandLookalikeLinks,
    jsDomMutationPayloads,
    dynamicContentAfterJsLikely,
    staticVsRenderedNote,
    externalJsInspectedCount,
    jsBehaviorSummary: {
      dynamicFormActionRewrite,
      passwordFieldDomHooks,
      walletDrainerPattern,
      antiDebugTraps,
      hiddenOverlayIframes,
      obfuscationMarkerCount: obfuscationMarkerMatches.length,
    },
    backgroundDataCollection,
    externalDataTransmissions,
  };

  // Findings generation for Source Intelligence, JS Behavior, HTML Semantics & Discovered Subdomains
  if (baseTagHijack) {
    findings.push({
      id: 'source-base-tag-hijack',
      section: 'source_intelligence',
      test: { en: 'Base HTML Tag Hijack Check', ar: 'فحص التلاعب بوسم القاعدة HTML <base>' },
      result: { en: `Deceptive <base href="${baseTagHref}"> points to external host`, ar: `وسم <base href="${baseTagHref}"> يشير لنطاق خارجي` },
      status: 'failed',
      severity: 'high',
      weight: 24,
      evidence: `Base href: ${baseTagHref}`,
      explanation: {
        en: 'A malicious <base> tag redirects all relative links and resource paths to an attacker-controlled domain.',
        ar: 'يعيد وسم <base> الخبيث توجيه كافة الروابط النسبية وملفات الموقع نحو خادم يسيطر عليه المهاجم.',
      },
      recommendedAction: {
        en: 'Do not interact with this page; base-tag hijacking is a classic phishing cloaking technique.',
        ar: 'لا تتفاعل مع هذه الصفحة؛ التلاعب بوسم القاعدة هو أسلوب تصيد كلاسيكي.',
      },
      source: 'SM Source Intelligence',
      timestamp: now,
      confidence: 98,
    });
  }

  // Source Finding A: JavaScript Static Behavioral Forensics
  const highJsSignals = suspiciousCodeSignals.filter((s) => s.riskLevel === 'high' || s.riskLevel === 'critical');
  const medJsSignals = suspiciousCodeSignals.filter((s) => s.riskLevel === 'medium');
  const hasSeriousJsBehavior =
    highJsSignals.length >= 1 ||
    (hasMaliciousObfuscationMarker && formExfiltrationHooks.length > 0) ||
    dynamicFormActionRewrite ||
    walletDrainerPattern;
  const hostOwnershipSrc = classifyDomainRelationship(finalHost, finalHost);
  const suppressSpaHookOnOfficial = hostOwnershipSrc.isSameOrganization && highJsSignals.every((s) => s.benignContextPossible);

  const jsBehaviorFailed = hasSeriousJsBehavior && !suppressSpaHookOnOfficial;
  const jsBehaviorWarn = !jsBehaviorFailed && medJsSignals.length > 0 && !suppressSpaHookOnOfficial;

  findings.push({
    id: 'source-js-behavior',
    section: 'javascript_analysis',
    test: { en: 'Deep Source & JavaScript Behavioral Inspection', ar: 'التحليل العميق لسورس الموقع وسلوكيات JavaScript' },
    result: jsBehaviorFailed
      ? {
          en: `${highJsSignals.length} high-risk JS pattern(s): ${highJsSignals.map((s) => s.indicator).slice(0, 2).join('; ')}`,
          ar: `رصد ${highJsSignals.length} سلوكاً خطيراً في أكواد JavaScript: ${highJsSignals.map((s) => s.indicator).slice(0, 2).join('؛ ')}`,
        }
      : jsBehaviorWarn
        ? {
            en: `${medJsSignals.length} defensive/anti-analysis JS indicator(s) recorded`,
            ar: `رصد ${medJsSignals.length} مؤشر تعطيل فحص في كود JavaScript`,
          }
        : isMinifiedBundlePresent && !hasMaliciousObfuscationMarker
          ? {
              en: `Inspected ${inlineJsCount} inline & ${externalJsFiles.length} external JS files (standard minified production bundles verified clean)`,
              ar: `فحص ${inlineJsCount} سكربت داخلي و ${externalJsFiles.length} خارجي (حزم مضغوطة قياسية سليمة دون تمويه خبيث)`,
            }
          : {
              en: `Inspected ${inlineJsCount} inline & ${externalJsFiles.length} external JS files — no exfiltration or malicious obfuscation detected`,
              ar: `فحص ${inlineJsCount} سكربت داخلي و ${externalJsFiles.length} خارجي — خالية من التمويه الخبيث وخطافات التسريب`,
            },
    status: jsBehaviorFailed ? 'failed' : jsBehaviorWarn ? 'warning' : 'pass',
    severity: jsBehaviorFailed ? 'high' : jsBehaviorWarn ? 'medium' : 'informational',
    weight: jsBehaviorFailed ? (highJsSignals.length >= 2 || dynamicFormActionRewrite || walletDrainerPattern ? 26 : 20) : jsBehaviorWarn ? 10 : 0,
    evidence: `InlineJS: ${inlineJsCount} | ExtJS: ${externalJsFiles.length} | MinifiedOnly: ${isMinifiedBundlePresent && !hasMaliciousObfuscationMarker} | HighSignals: [${highJsSignals.map((s) => s.indicator).join(', ') || 'none'}] | ExfilHooks: [${formExfiltrationHooks.join('; ') || 'none'}] | StorageAccess: [${storageAndCookieAccess.join(', ') || 'none'}]`,
    explanation: {
      en: jsBehaviorFailed
        ? 'Static inspection of retrieved JavaScript code identified high-risk runtime patterns such as encoded eval() unpacking, obfuscated _0x arrays, dynamic form.action rewriting, or background credential/clipboard exfiltration.'
        : 'Deep static reading of page scripts confirmed clean code patterns without encoded payload unpacking or hidden credential exfiltration hooks.',
      ar: jsBehaviorFailed
        ? 'كشف الفحص الفعلي لسورس JavaScript عن أنماط برمجية عالية الخطورة مثل فك تشفير وتشغيل eval أو مصفوفات _0x المشوشة أو تغيير وجهة إرسال النماذج أو تسريب البيانات في الخلفية.'
        : 'أكدت قراءة سورس JavaScript الفعلي سلامة الأكواد وخلوها من التعتيم الخبيث أو خطافات سرقة البيانات.',
    },
    recommendedAction: {
      en: jsBehaviorFailed ? 'Do not enter credentials or allow clipboard/wallet access on this page.' : 'No action required.',
      ar: jsBehaviorFailed ? 'لا تُدخل أي بيانات أو تمنح صلاحيات للحافظة أو المحفظة في هذه الصفحة.' : 'لا يلزم إجراء.',
    },
    source: 'SM Deep Source & JS Forensics',
    timestamp: now,
    confidence: jsBehaviorFailed ? 94 : 90,
  });

  // Source Finding A2: Background JS Data Collection & External Service Exfiltration
  const suspiciousExternalTx = externalDataTransmissions.filter(
    (t) => t.relationshipStatus === 'external_unknown' || t.relationshipStatus === 'suspicious_lookalike' || t.obfuscatedUrl
  );
  const sensitiveBgCollection = backgroundDataCollection.filter(
    (b) =>
      b.category === 'cookies_storage' ||
      b.category === 'credentials_inputs' ||
      b.category === 'keystrokes_clipboard' ||
      b.category === 'browser_fingerprinting' ||
      b.category === 'device_network_webrtc'
  );
  const hasHighRiskBgExfil =
    (sensitiveBgCollection.length > 0 && suspiciousExternalTx.length > 0) ||
    suspiciousExternalTx.some((t) => t.obfuscatedUrl && t.isThirdParty) ||
    suspiciousExternalTx.some((t) => t.relationshipStatus === 'suspicious_lookalike');
  const hasMediumBgCollectionWarn =
    !hasHighRiskBgExfil &&
    (suspiciousExternalTx.length > 0 || backgroundDataCollection.some((b) => b.riskLevel === 'high'));

  if (backgroundDataCollection.length > 0 || externalDataTransmissions.length > 0) {
    findings.push({
      id: 'source-background-exfiltration',
      section: 'javascript_analysis',
      test: {
        en: 'Background JS Data Collection & External Service Transmission',
        ar: 'كشف جمع البيانات بالخلفية عبر JavaScript وإرسالها لخدمات خارجية',
      },
      result: hasHighRiskBgExfil
        ? {
            en: `Collected ${sensitiveBgCollection.map((b) => b.category).join(', ') || 'page data'} in background & transmitted to ${suspiciousExternalTx.map((t) => t.destinationHost).slice(0, 3).join(', ')}`,
            ar: `جمع بيانات بالخلفية (${sensitiveBgCollection.map((b) => b.title.ar).slice(0, 2).join(' + ') || 'بيانات المتصفح'}) وإرسالها إلى خدمة خارجية (${suspiciousExternalTx.map((t) => t.destinationHost).slice(0, 3).join('، ')})`,
          }
        : hasMediumBgCollectionWarn
          ? {
              en: `Detected ${backgroundDataCollection.length} background collector(s) and ${suspiciousExternalTx.length} external service endpoint(s)`,
              ar: `رصد ${backgroundDataCollection.length} آلية جمع بالخلفية و ${suspiciousExternalTx.length} وجهة إرسال خارجية`,
            }
          : {
              en: `Detected ${backgroundDataCollection.length} background read(s) & ${externalDataTransmissions.length} same-org/authorized transmission(s)`,
              ar: `رصد ${backgroundDataCollection.length} قراءة بالخلفية و ${externalDataTransmissions.length} اتصال ضمن نفس النطاق أو مزود معتمد`,
            },
      status: hasHighRiskBgExfil ? 'failed' : hasMediumBgCollectionWarn ? 'warning' : 'pass',
      severity: hasHighRiskBgExfil ? 'high' : hasMediumBgCollectionWarn ? 'medium' : 'informational',
      weight: hasHighRiskBgExfil ? (suspiciousExternalTx.some((t) => t.obfuscatedUrl) ? 30 : 26) : hasMediumBgCollectionWarn ? 12 : 0,
      evidence: `BgCollectors: [${backgroundDataCollection.map((b) => `${b.category}(${b.apisUsed.join('+')})`).join('; ') || 'none'}] | ExternalTx: [${externalDataTransmissions.map((t) => `${t.method}:${t.destinationUrl}(${t.relationshipStatus}${t.obfuscatedUrl ? ',obfuscated' : ''})`).join('; ') || 'none'}]`,
      explanation: {
        en: hasHighRiskBgExfil
          ? 'Scripts silently harvest cookies, storage, inputs, keystrokes, or device fingerprints in the background and transmit them to an unverified or obfuscated external server.'
          : hasMediumBgCollectionWarn
            ? 'JavaScript references external endpoints or sensitive browser data APIs; inspect destination details in the Background Telemetry card.'
            : 'Observed script network calls stay within same-organization endpoints or recognized third-party providers without secret harvesting.',
        ar: hasHighRiskBgExfil
          ? 'يقوم كود JavaScript بجمع بيانات حساسة في الخلفية (مثل الكوكيز أو التخزين أو ضغطات المفاتيح أو بصمة الجهاز) وإرسالها صامتاً عبر fetch/XHR/sendBeacon/WebSocket إلى خدمة خارجية غير موثوقة أو مموهة.'
          : hasMediumBgCollectionWarn
            ? 'يتواصل السكربت مع وجهات خارجية أو يقرأ خصائص المتصفح؛ راجع تفاصيل الوجهات والبيانات المجموعة في قسم الإرسال بالخلفية.'
            : 'تقتصر طلبات الشبكة المرصودة على نطاق الموقع نفسه أو مزودين معتمدين دون سرقة بيانات.',
      },
      recommendedAction: {
        en: hasHighRiskBgExfil
          ? 'Avoid signing in or entering sensitive data; inspect the exact external destinations listed below.'
          : 'Review detected endpoints if unexpected.',
        ar: hasHighRiskBgExfil
          ? 'لا تدخل أي بيانات شخصية أو كلمات مرور في هذه الصفحة وراجع تفاصيل الخوادم الخارجية المستلمة أدناه.'
          : 'راجع قائمة الوجهات إذا لم تكن متوقعة.',
      },
      source: 'SM JS Telemetry & Exfiltration Tracer',
      timestamp: now,
      confidence: hasHighRiskBgExfil ? 94 : 88,
    });
  }

  // Source Finding B: HTML Semantics, Title-vs-Body & Clickjacking Structure
  let metaRefreshExternal = false;
  if (metaRefresh) {
    const urlPart = metaRefresh.match(/url\s*=\s*['"]?([^'";\s]+)/i)?.[1];
    if (urlPart) {
      try {
        const u = new URL(urlPart, finalUrl);
        if (extractRegistrableDomain(u.hostname) !== finalRegDomain && !classifyDomainRelationship(finalHost, u.hostname).isBenignOrAuthorized) {
          metaRefreshExternal = true;
        }
      } catch {
        // ignore
      }
    }
  }
  const crossOriginFormActionAttr = suspiciousAttributes.some((a) => a.attribute === 'formaction');
  const hasHtmlStructureFail = titleContentMismatch || metaRefreshExternal || crossOriginFormActionAttr;
  const hasHtmlStructureWarn = !hasHtmlStructureFail && hiddenOverlayIframes > 0;

  findings.push({
    id: 'source-html-structure',
    section: 'source_intelligence',
    test: { en: 'HTML DOM Structure, Meta & Title Integrity', ar: 'فحص بنية HTML وسلامة العنوان والوسوم المخفية' },
    result: titleContentMismatch && titleMismatchDetail
      ? titleMismatchDetail
      : metaRefreshExternal
        ? { en: `External <meta http-equiv="refresh"> redirects off-domain (${metaRefresh?.slice(0, 60)})`, ar: `وسم <meta refresh> يحوّل إلى نطاق خارجي غير مرتبط` }
        : crossOriginFormActionAttr
          ? { en: 'Button formaction attribute overrides submission to external domain', ar: 'سمة formaction تعيد توجيه إرسال النموذج إلى نطاق خارجي' }
          : hiddenOverlayIframes > 0
            ? { en: `${hiddenOverlayIframes} invisible/off-screen iframe overlay detected in HTML`, ar: `رصد ${hiddenOverlayIframes} إطار iframe مخفي قد يُستخدم لخطف النقرات` }
            : {
                en: `HTML structure verified clean (${hiddenInputs.length} hidden inputs, 0 external meta redirects, consistent <title>)`,
                ar: `بنية HTML متسقة وسليمة (${hiddenInputs.length} مدخلات مخفية، 0 تحويلات meta خارجية، عنوان متطابق)`,
              },
    status: hasHtmlStructureFail ? 'failed' : hasHtmlStructureWarn ? 'warning' : 'pass',
    severity: hasHtmlStructureFail ? 'high' : hasHtmlStructureWarn ? 'medium' : 'informational',
    weight: hasHtmlStructureFail ? 20 : hasHtmlStructureWarn ? 10 : 0,
    evidence: `TitleMismatch: ${titleContentMismatch} | MetaRefreshExternal: ${metaRefreshExternal} | CrossOriginFormaction: ${crossOriginFormActionAttr} | HiddenOverlayIframes: ${hiddenOverlayIframes} | JSON-LD: ${jsonLdCount}`,
    explanation: {
      en: hasHtmlStructureFail
        ? 'Retrieved HTML markup contains deceptive metadata (<title> brand mismatch against body copy, off-domain meta refresh redirect, or cross-origin formaction override).'
        : 'Retrieved HTML markup semantics (<title>, meta tags, form targets, iframes) align consistently with the page domain.',
      ar: hasHtmlStructureFail
        ? 'يكشف فحص كود HTML الفعلي عن تلاعب واضح في البنية أو انتحال في وسم <title> مقابل المحتوى أو إعادة توجيه مخفية.'
        : 'وسوم HTML وبنية الصفحة تتطابق بسلاسة مع النطاق والغرض المعروض.',
    },
    recommendedAction: {
      en: hasHtmlStructureFail ? 'Verify the true domain and avoid submitting data on pages with conflicting metadata.' : 'No action required.',
      ar: hasHtmlStructureFail ? 'تحقق من النطاق الحقيقي وتجنب إدخال البيانات في صفحات متضاربة البنية.' : 'لا يلزم إجراء.',
    },
    source: 'SM HTML Source Inspector',
    timestamp: now,
    confidence: 92,
  });

  // Source Finding C: In-Page Discovered Subdomains & Third-Party Topology
  const suspiciousSubdomains = discoveredSubdomains.filter((s) => s.suspiciousRole);
  findings.push({
    id: 'source-discovered-subdomains',
    section: 'source_intelligence',
    test: { en: 'Discovered Site Subdomains & Reference Topology', ar: 'اكتشاف النطاقات الفرعية وروابط البنية داخل الموقع' },
    result:
      discoveredSubdomains.length > 0
        ? {
            en: `${discoveredSubdomains.length} sibling subdomain(s) discovered under ${finalRegDomain}: ${discoveredSubdomains.slice(0, 4).map((s) => s.host).join(', ')}`,
            ar: `تم اكتشاف ${discoveredSubdomains.length} نطاق فرعي ضمن ${finalRegDomain}: ${discoveredSubdomains.slice(0, 4).map((s) => s.host).join('، ')}`,
          }
        : {
            en: `No additional subdomains under ${finalRegDomain} referenced in page HTML (${externalDomainsSet.size} external resource host(s))`,
            ar: `لم ترد نطاقات فرعية إضافية تحت ${finalRegDomain} في كود الصفحة (${externalDomainsSet.size} مضيف موارد خارجي)`,
          },
    status: suspiciousSubdomains.length > 0 ? 'warning' : 'pass',
    severity: 'informational',
    weight: 0,
    evidence: `Subdomains[${discoveredSubdomains.length}]: [${discoveredSubdomains.map((s) => `${s.host}(${s.role})`).join(', ') || 'none'}] | ExtResourceDomains: [${Array.from(externalDomainsSet).slice(0, 8).join(', ') || 'none'}]`,
    explanation: {
      en: 'Enumerates subdomains and external asset origins referenced directly inside HTML anchors, scripts, forms, stylesheets, and inline JavaScript.',
      ar: 'يستخرج النطاقات الفرعية ومصادر الموارد المذكورة داخل كود HTML والنماذج والسكربتات لتحليل البنية الفعلية للموقع.',
    },
    recommendedAction: {
      en: 'Inspect unfamiliar authentication or admin subdomains discovered inside third-party pages.',
      ar: 'راجع أي نطاقات فرعية غريبة مرتبطة بتسجيل الدخول أو الإرسال.',
    },
    source: 'SM Subdomain & Source Mapper',
    timestamp: now,
    confidence: 90,
  });

  if (brandLookalikeLinks.length > 0) {
    findings.push({
      id: 'source-brand-lookalike-links',
      section: 'source_intelligence',
      test: { en: 'Outbound Brand-Lookalike Link Analysis', ar: 'فحص الروابط الصادرة المشابهة للعلامات التجارية' },
      result: {
        en: `${brandLookalikeLinks.length} outbound link(s)/form(s) point to brand-lookalike host (${brandLookalikeLinks[0].host})`,
        ar: `رصد ${brandLookalikeLinks.length} رابط أو نموذج يشير إلى نطاق مشابه لعلامة تجارية (${brandLookalikeLinks[0].host})`,
      },
      status: 'warning',
      severity: 'medium',
      weight: 14,
      evidence: brandLookalikeLinks.map((l) => `${l.host} -> ${l.targetBrand} (${l.officialDomain})`).join(' | '),
      explanation: {
        en: 'Source code inspection identified outbound hyperlinks or form endpoints pointing to domains that imitate well-known official brands.',
        ar: 'كشف تحليل السورس عن روابط أو وجهات نماذج تشير إلى نطاقات تتشابه اسمياً مع علامات تجارية رسمية معروفة.',
      },
      recommendedAction: {
        en: 'Verify any outbound authentication or payment links before following them.',
        ar: 'تحقق من أي روابط أو وجهات إرسال قبل الانتقال إليها.',
      },
      source: 'SM Source Link Analyzer',
      timestamp: now,
      confidence: 88,
    });
  }

  if (!securityHeaders.csp) {
    findings.push({
      id: 'source-csp-missing',
      section: 'source_intelligence',
      test: { en: 'Content Security Policy (CSP) Header', ar: 'ترويسة سياسة أمان المحتوى (CSP)' },
      result: { en: 'Content-Security-Policy header is missing', ar: 'ترويسة Content-Security-Policy مفقودة' },
      status: 'warning',
      severity: 'informational',
      weight: 0,
      evidence: 'Missing CSP header in HTTP response',
      explanation: {
        en: 'Absence of a Content Security Policy allows browser execution of injected scripts if an XSS vulnerability occurs.',
        ar: 'غياب سياسة CSP يتيح للمتصفح تنفيذ أي سكربت محقون في حال وجود ثغرة XSS.',
      },
      recommendedAction: {
        en: 'Implement a strict CSP policy in production.',
        ar: 'تفعيل سياسة CSP صارمة في بيئة الإنتاج.',
      },
      source: 'SM Header Inspector',
      timestamp: now,
      confidence: 100,
    });
  }

  return { sourceIntel, formDetails, supplyChain, findings };
}
