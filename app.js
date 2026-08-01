const $ = (id) => document.getElementById(id);

let currentKey = "";

function setMessage(text, type = "") {
  const message = $("message");

  if (!message) return;

  message.textContent = text;
  message.className = `message ${type}`.trim();
}

async function api(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json"
    },
    body: JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({
    ok: false,
    error: "Phản hồi máy chủ không hợp lệ."
  }));

  if (!response.ok || !data.ok) {
    throw new Error(
      data.error || "Yêu cầu thất bại."
    );
  }

  return data;
}

function formatExpiry(value) {
  if (!value) return "Không xác định";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Không xác định";
  }

  return date.toLocaleString("vi-VN");
}

function showKey(data) {
  if (!data || !data.key) {
    throw new Error(
      "Máy chủ không trả về key."
    );
  }

  currentKey = data.key;

  $("keyValue").textContent = data.key;

  $("planValue").textContent =
    `${data.planHours || 24} giờ`;

  $("expiresValue").textContent =
    formatExpiry(data.expiresAt);

  $("statusBadge").textContent =
    String(
      data.status || "ACTIVE"
    ).toUpperCase();

  $("result").classList.remove("hidden");

  localStorage.setItem(
    "sent_last_key",
    JSON.stringify(data)
  );

  $("result").scrollIntoView({
    behavior: "smooth",
    block: "center"
  });
}

function setGenerateButtonLoading(
  loading,
  text = "Generate"
) {
  const button = $("generateBtn");

  if (!button) return;

  button.disabled = loading;

  button.innerHTML = loading
    ? `<span>⌛</span><span>${text}</span>`
    : "<span>⇥</span><span>Generate</span>";
}

async function startLink4m() {
  try {
    setGenerateButtonLoading(
      true,
      "Đang tạo link..."
    );

    setMessage(
      "Đang tạo liên kết Link4m..."
    );

    const result = await api(
      "/api/link4m/start",
      {}
    );

    if (!result.shortUrl) {
      throw new Error(
        "Không nhận được liên kết Link4m."
      );
    }

    setMessage(
      "Đang chuyển sang Link4m...",
      "success"
    );

    window.location.assign(
      result.shortUrl
    );
  } catch (error) {
    setMessage(
      error.message ||
        "Không thể mở Link4m.",
      "error"
    );

    setGenerateButtonLoading(false);
  }
}

async function completeLink4m(
  sessionToken
) {
  try {
    setGenerateButtonLoading(
      true,
      "Đang xác nhận..."
    );

    setMessage(
      "Đang xác nhận phiên Link4m..."
    );

    const result = await api(
      "/api/link4m/complete",
      {
        sessionToken
      }
    );

    showKey(result.data);

    setMessage(
      result.reused
        ? "Đã khôi phục key của phiên này."
        : "Vượt Link4m thành công. Key 24H đã được tạo.",
      "success"
    );

    window.history.replaceState(
      {},
      document.title,
      window.location.pathname
    );
  } catch (error) {
    setMessage(
      error.message ||
        "Không thể xác nhận Link4m.",
      "error"
    );
  } finally {
    setGenerateButtonLoading(false);
  }
}

async function copyKey() {
  if (!currentKey) return;

  const button = $("copyBtn");

  try {
    await navigator.clipboard.writeText(
      currentKey
    );
  } catch {
    const temporaryInput =
      document.createElement("textarea");

    temporaryInput.value = currentKey;
    temporaryInput.style.position = "fixed";
    temporaryInput.style.opacity = "0";

    document.body.appendChild(
      temporaryInput
    );

    temporaryInput.select();
    document.execCommand("copy");
    temporaryInput.remove();
  }

  button.textContent = "Đã sao chép ✓";

  setTimeout(() => {
    button.textContent = "Sao chép key";
  }, 1500);
}

function restoreSavedKey() {
  const saved = localStorage.getItem(
    "sent_last_key"
  );

  if (!saved) return;

  try {
    const data = JSON.parse(saved);

    const expiryTime = new Date(
      data.expiresAt
    ).getTime();

    if (
      Number.isFinite(expiryTime) &&
      expiryTime > Date.now()
    ) {
      showKey(data);
    } else {
      localStorage.removeItem(
        "sent_last_key"
      );
    }
  } catch {
    localStorage.removeItem(
      "sent_last_key"
    );
  }
}

$("generateBtn")?.addEventListener(
  "click",
  startLink4m
);

$("copyBtn")?.addEventListener(
  "click",
  copyKey
);

$("closeWelcome")?.addEventListener(
  "click",
  () => {
    document
      .querySelector(".welcome-card")
      ?.classList.add("hidden");
  }
);

const urlParams = new URLSearchParams(
  window.location.search
);

const sessionToken =
  urlParams.get("session");

if (sessionToken) {
  completeLink4m(sessionToken);
} else {
  restoreSavedKey();
}
