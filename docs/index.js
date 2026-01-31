// دالة حساب مسافة ليفنشتاين (لاكتشاف تشابه النطاقات)
function getEditDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // استبدال
          matrix[i][j - 1] + 1,     // إدخال
          matrix[i - 1][j] + 1      // حذف
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

// عناصر الواجهة
const urlInput = document.getElementById('urlInput');
const scanButton = document.getElementById('scanButton');
const resultBox = document.getElementById('resultBox');

scanButton.addEventListener('click', handleScan);

// تحليل الرابط
function parseUrl(url) {
  try {
    const link = url.startsWith('http') ? url : `https://${url}`;
    const parsed = new URL(link);
    return {
      fullUrl: url,
      protocol: parsed.protocol.replace(':', ''),
      domain: parsed.hostname,
      path: parsed.pathname + parsed.search + parsed.hash,
      length: url.length,
      isHttps: parsed.protocol === 'https:',
      isShortened: /bit\.ly|t\.co|tinyurl|goo\.gl|cutt\.ly|cli\.gs|t\.ly/i.test(url)
    };
  } catch (e) {
    return null;
  }
}

// القائمة البيضاء للنطاقات الموثوقة
const ultraSafeDomains = [
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com','wikipedia.org',
  'tiktok.com', 'apple.com', 'samsung.com', 'huawei.com', 'amazon.sa', 'amazon.com',
  'whatsapp.com', 'github.com', 'microsoft.com', 'speedtest.net', 'wikipedia.org',
  'linkedin.com', 'reddit.com', 'cisco.com', 'bing.com', 'yahoo.com', 'netflix.com',
  'paypal.com', 'ebay.com', 'adobe.com', 'oracle.com', 'ibm.com', 'dell.com', 'hp.com',
  'alipay.com', 'tencent.com', 'baidu.com', 'weibo.com', 'vk.com',
  'gov.sa', 'edu.sa', 'saudibanks.sa', 'stc.com.sa', 'mobily.com.sa', 'zeker.sa',
  'absher.sa', 'elm.sa', 'mof.gov.sa', 'cma.org.sa', 'sama.gov.sa', 'moe.gov.sa'
  , 'ksu.edu.sa', 'tuwaiq.edu.sa', 'mcit.gov.sa', 'nic.gov.sa',
  'yesser.gov.sa', 'saudi.gov.sa'
];

async function handleScan() {
  const url = urlInput.value.trim();

  if (!url) {
    alert('الرجاء إدخال رابط للفحص');
    return;
  }

  const urlDetails = parseUrl(url);

  if (!urlDetails) {
    alert('صيغة الرابط غير صحيحة.');
    return;
  }

  scanButton.disabled = true;
  scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> جاري التحليل...';
  resultBox.style.display = 'none';

  let securityLevel = 'safe';
  let suspiciousPatterns = [];

  const domainToCheck = urlDetails.domain.toLowerCase();
  const cleanDomain = domainToCheck.startsWith('www.') ? domainToCheck.substring(4) : domainToCheck;

  const isExactMatch = ultraSafeDomains.some(d => cleanDomain === d);

  // 1) بروتوكول HTTP
  if (urlDetails.protocol === 'http') {
    suspiciousPatterns.push('الرابط غير مشفّر (HTTP) ويسهل اعتراض بياناته. *(خطر عالي)*');
  }

  // 2) الروابط المختصرة
  if (urlDetails.isShortened) {
    suspiciousPatterns.push('الرابط مُختصر، مما يصعّب التحقق من الوجهة النهائية. *(خطر عالي)*');
  }

  // 3) كلمات مفتاحية مشبوهة
  const suspiciousWords = [
    'scam', 'login-verify', 'free-soft', 'update-now',
    'payment-failed', 'security-alert', 'download-exe',
    'account-sync', 'support-fix'
  ];
  const lowerCaseUrl = url.toLowerCase();

  suspiciousWords.forEach(word => {
    if (lowerCaseUrl.includes(word)) {
      suspiciousPatterns.push(`الرابط يحتوي على كلمة مفتاحية مشبوهة: "${word}".`);
    }
  });

  let isTyposquattingDetected = false;

  for (const safeDomain of ultraSafeDomains) {
    const tldIndex = cleanDomain.lastIndexOf('.');
    const nameToCheck = tldIndex > 0 ? cleanDomain.substring(0, tldIndex) : cleanDomain;

    const safeTldIndex = safeDomain.lastIndexOf('.');
    const safeName = safeTldIndex > 0 ? safeDomain.substring(0, safeTldIndex) : safeDomain;

    const distance = getEditDistance(nameToCheck, safeName);

    if (distance === 1) {
      suspiciousPatterns.push(
        `النطاق قريب جداً من نطاق مشهور (${safeDomain}) باختلاف حرف واحد، وهو مؤشر قوي على التلاعب بالنطاق (Typosquatting).`
      );
      isTyposquattingDetected = true;
      securityLevel = 'danger';
      break;
    }
  }

  if (!isExactMatch) {
    const domainNoTLD = cleanDomain.substring(0, cleanDomain.lastIndexOf('.'));
    const digitCount = (domainNoTLD.match(/\d/g) || []).length;
    const hyphenCount = (domainNoTLD.match(/-/g) || []).length;
    const suspiciousChars = /[^a-z0-9-.]/.test(cleanDomain);

    suspiciousPatterns.push('النطاق غير موجود في قائمة النطاقات الموثوقة، يُنصح بالتعامل معه بحذر.');

    if (!isTyposquattingDetected) {
      if (digitCount > 0) {
        suspiciousPatterns.push('النطاق غير معروف ويحتوي على أرقام في الاسم.');
      }

      if (hyphenCount > 0) {
        suspiciousPatterns.push('النطاق غير معروف ويحتوي على شرطات (-).');
      }

      if (cleanDomain.length > 35) {
        suspiciousPatterns.push('النطاق الأساسي طويل جداً (أكثر من 35 حرفاً) ومجهول.');
      }
    }

    if (suspiciousChars) {
      suspiciousPatterns.push('تم الكشف عن رموز أو أحرف غير قياسية في النطاق (قد تكون Punycode/Unicode للتضليل).');
    }

    if (suspiciousPatterns.length > 0) {
      securityLevel = 'danger';
    }
  }

  if (domainToCheck.includes('google.com') && url.includes('/aclk?')) {
    if (urlDetails.path.length < 50 || urlDetails.path.length > 700) {
      suspiciousPatterns.push('طول مسار التتبع على Google غير طبيعي (إضافة أو حذف كبير في البصمة).');
      securityLevel = 'danger';
    }

    if (urlDetails.path.includes('//') || urlDetails.path.includes('..') || !urlDetails.path.includes('&sig=')) {
      suspiciousPatterns.push('تم الكشف عن رموز غير مألوفة أو مفقود جزء التوقيع (&sig) في مسار التتبع.');
      securityLevel = 'danger';
    }
  }

  if (isExactMatch && urlDetails.path !== '/') {
    const path = urlDetails.path;

    if (urlDetails.length > 80 && !url.includes('watch?v=') && !url.includes('/aclk?')) {
      suspiciousPatterns.push('الرابط مطابق لنطاق آمن لكنه طويل بشكل غير طبيعي، قد يشير إلى مسار تتبع أو محتوى غير موثوق.');
    }

    if (path.includes('../') || path.includes('//')) {
      suspiciousPatterns.push('المسار يحتوي على رموز غير عادية (مثل // أو ../) تستخدم في هجمات المسارات.');
    }

    if (cleanDomain.includes('absher.sa') ){
      const knownAbsherPath = '/wps/portal/business';

      if (
        (cleanDomain.includes('absher.sa') &&
          getEditDistance(path.substring(0, 20), knownAbsherPath.substring(0, 20)) > 3) ) {
        suspiciousPatterns.push('تم الكشف عن تلاعب بسيط في مسار بوابة حكومية معروفة (Absher/.');
      }
    }

    if (suspiciousPatterns.some(p =>
      p.includes('المسار يحتوي') || p.includes('رموز غير عادية') || p.includes('تلاعب بسيط')
    )) {
      securityLevel = 'danger';
    }
  }

  // 7) رابط EICAR/WICAR للاختبار
  if (url.includes('wicar.org')) {
    securityLevel = 'danger';
    suspiciousPatterns.push('تم التعرف على هذا الرابط كملف اختبار ضار (EICAR/WICAR).');
  }

  // 8) القرار النهائي
  if (securityLevel === 'danger' || suspiciousPatterns.length >= 1) {
    securityLevel = 'danger';
  } else {
    securityLevel = 'safe';
  }

  // تأخير بسيط للواجهة فقط
  await new Promise(resolve => setTimeout(resolve, 1000));

  displayResult(securityLevel, urlDetails, suspiciousPatterns);
  scanButton.disabled = false;
  scanButton.innerHTML = '<i class="fas fa-search"></i> فحص متقدم';
}

// عرض النتيجة في الواجهة
function displayResult(level, details, patterns) {
  resultBox.className = 'result-box';
  resultBox.classList.add(level);

  let iconHtml;
  let statusText;

  if (level === 'safe') {
    iconHtml = '<i class="fas fa-check-circle"></i>';
    statusText = 'آمن تماماً';
  } else {
    iconHtml = '<i class="fas fa-exclamation-triangle"></i>';
    statusText = 'خطر / مشبوه';
  }

  let warningsHtml = '';
  if (patterns.length > 0) {
    const listItems = patterns.map(p => `<li>${p}</li>`).join('');
    warningsHtml = `
      <div class="warnings-list">
          <p class="warnings-title">🔴 تم اكتشاف (${patterns.length}) مؤشر خطر:</p>
          <ul>${listItems}</ul>
      </div>
    `;
  } else if (level === 'safe') {
    warningsHtml = `
      <div class="warnings-list safe" style="border-color:#059669; background-color:#ECFDF5;">
          <p class="warnings-title" style="color:#059669;">
              ✅ تقييم الأمان: مطابق تماماً لنطاق آمن ولا يوجد اشتباه.
          </p>
      </div>
    `;
  }

  resultBox.innerHTML = `
    <div class="result-header">
        ${iconHtml}
        <span class="result-status">${statusText}</span>
    </div>
    <p class="result-url">${details.fullUrl}</p>

    <div class="details-grid">
        <div class="detail-item">
            <span class="detail-label">البروتوكول:</span>
            <span class="detail-value" style="color: ${details.isHttps ? '#059669' : '#DC2626'};">
              ${details.protocol.toUpperCase()}
            </span>
        </div>
        <div class="detail-item">
            <span class="detail-label">النطاق:</span>
            <span class="detail-value" dir="ltr">${details.domain}</span>
        </div>
        <div class="detail-item">
            <span class="detail-label">طول الرابط:</span>
            <span class="detail-value">${details.length} حرف</span>
        </div>
        <div class="detail-item">
            <span class="detail-label">اختصار الرابط:</span>
            <span class="detail-value" style="color: ${details.isShortened ? '#F59E0B' : '#059669'};">
              ${details.isShortened ? 'نعم (مشبوه)' : 'لا'}
            </span>
        </div>
    </div>

    ${warningsHtml}
  `;
  resultBox.style.display = 'block';
}
// ================= QR SCAN (ADD ONLY) =================
const qrButton = document.getElementById('qrButton');
const qrReader = document.getElementById('qrReader');

let qrScanner = null;

if (qrButton) {
  qrButton.addEventListener('click', async () => {
    qrReader.style.display = 'block';

    if (!qrScanner) {
      qrScanner = new Html5Qrcode('qrReader');
    }

    try {
      await qrScanner.start(
        { facingMode: 'environment' },
        { fps: 10, qrbox: 250 },
        (qrText) => {
          if (!qrText) return;

          // وضع الرابط في input الموجود أصلاً
          urlInput.value = qrText;

          // إيقاف الكاميرا
          qrScanner.stop().then(() => {
            qrReader.style.display = 'none';

            // تشغيل نفس الفحص القديم بدون أي تغيير
            handleScan();
          });
        },
        () => {}
      );
    } catch (e) {
      alert('تعذر تشغيل الكاميرا');
      console.error(e);
    }
  });
}

