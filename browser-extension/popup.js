const siteNameElement = document.getElementById('siteName');
const resultDiv = document.getElementById('result');
const vtApiKeyInput = document.getElementById('vtApiKey');

async function loadVirusTotalKey() {
  if (!chrome?.storage?.local) {
    return;
  }
  chrome.storage.local.get(['vtApiKey'], (items) => {
    if (items.vtApiKey) {
      vtApiKeyInput.value = items.vtApiKey;
    }
  });
}

function saveVirusTotalKey(value) {
  if (!chrome?.storage?.local) {
    return;
  }
  chrome.storage.local.set({ vtApiKey: value });
}

function getDomainFromUrl(url) {
  try {
    const { hostname } = new URL(url);
    return hostname;
  } catch (error) {
    return url;
  }
}

document.getElementById('check').addEventListener('click', async () => {
  resultDiv.innerHTML = '<div class="detail">Checking current site...</div>';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url || '';
    const hostname = getDomainFromUrl(url);
    siteNameElement.querySelector('span').textContent = hostname;

    const response = await fetch('http://localhost:8000/predict_phishing', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error('Server error');
    }

    const data = await response.json();
    const score = Number(data.score.toFixed(2));
    const isPhishing = Boolean(data.is_phishing);

    const statusClass = isPhishing ? 'phishing' : 'safe';
    const statusText = isPhishing ? 'Phishing Detected' : 'Safe';
    const scorePercent = Math.min(Math.max(score * 100, 0), 100);

    resultDiv.innerHTML = `
      <div class="status ${statusClass}">${statusText}</div>
      <div class="score-bar"><div class="score-progress" style="width: ${scorePercent}%; background: ${isPhishing ? '#dc2626' : '#2563eb'}"></div></div>
      <div class="detail">Model score: ${score} / 1.00</div>
      <div class="vt-result" id="vtResult">Checking VirusTotal result...</div>
    `;

    const vtKey = vtApiKeyInput.value.trim();
    const vtResultDiv = document.getElementById('vtResult');
    if (vtKey) {
      try {
        const vtData = await checkVirusTotal(url, vtKey);
        vtResultDiv.innerHTML = formatVirusTotalResult(vtData);
      } catch (vtError) {
        vtResultDiv.innerHTML = `<div class="vt-status">VirusTotal error:</div><div class="detail">${vtError.message}</div>`;
      }
    } else {
      vtResultDiv.innerHTML = '<div class="vt-status">VirusTotal result:</div><div class="detail">No API key configured. Enter your VirusTotal API key above to enable this check.</div>';
    }
  } catch (e) {
    resultDiv.innerHTML = '<div class="detail">Error: Could not check site. Make sure the backend server is running.</div>';
  }
});

vtApiKeyInput.addEventListener('change', () => {
  saveVirusTotalKey(vtApiKeyInput.value.trim());
});

window.addEventListener('DOMContentLoaded', loadVirusTotalKey);

function formatVirusTotalResult(vtData) {
  if (!vtData) {
    return '<div class="vt-status">VirusTotal result:</div><div class="detail">No result available.</div>';
  }

  const { status, malicious, suspicious, undetected, harmless, total, analysisUrl } = vtData;
  let verdict;
  let verdictClass;

  if (status === 'queued' || total === 0) {
    verdict = 'Analysis pending';
    verdictClass = 'vt-pending';
  } else if (malicious > 0) {
    verdict = 'Malicious / Suspicious';
    verdictClass = 'phishing';
  } else {
    verdict = 'No malicious detections';
    verdictClass = 'safe';
  }

  return `
    <h4>VirusTotal API Result</h4>
    <div class="vt-status ${verdictClass}">${verdict}</div>
    <div class="detail">Status: ${status}</div>
    <div class="detail">Detections: ${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless, ${undetected} undetected</div>
    <div class="detail">Total engines: ${total}</div>
    <div class="detail"><a href="${analysisUrl}" target="_blank" rel="noreferrer">View full VirusTotal analysis</a></div>
  `;
}

async function checkVirusTotal(url, apiKey) {
  const requestBody = new URLSearchParams({ url });
  const createResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'x-apikey': apiKey
    },
    body: requestBody.toString()
  });

  if (!createResponse.ok) {
    const errorBody = await createResponse.text();
    if (createResponse.status === 429) {
      throw new Error('VirusTotal rate limit exceeded. Please wait or use a different API key.');
    }
    throw new Error(`VirusTotal API failed: ${createResponse.status} ${errorBody}`);
  }

  const createData = await createResponse.json();
  const analysisId = createData?.data?.id;
  if (!analysisId) {
    throw new Error('VirusTotal analysis ID not returned');
  }

  const getAnalysis = async () => {
    const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': apiKey
      }
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`VirusTotal analysis fetch failed: ${response.status} ${errorBody}`);
    }

    return response.json();
  };

  let analysisData = await getAnalysis();
  let attributes = analysisData?.data?.attributes;
  let stats = attributes?.stats || {};
  let attempt = 0;
  const maxAttempts = 5;
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  while (attributes?.status === 'queued' && attempt < maxAttempts) {
    attempt += 1;
    await wait(1500);
    analysisData = await getAnalysis();
    attributes = analysisData?.data?.attributes;
    stats = attributes?.stats || {};
  }

  const resource = analysisData?.meta?.file_info?.resource || analysisId;
  const analysisUrl = `https://www.virustotal.com/gui/url/${resource}/detection`;

  return {
    status: attributes?.status || 'unknown',
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
    analysisUrl
  };
}
