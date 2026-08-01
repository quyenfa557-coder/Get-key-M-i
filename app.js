const $ = (id) => document.getElementById(id);

let currentKey = "";

function setMessage(text, type = "") {
  const message = $("message");

  message.textContent = text;
  message.className = `message ${type}`.trim();
}

async function api(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "application/json"
    },
    body: JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({
    ok: false,
    error: "Phản hồi máy chủ không hợp lệ."
  }));

  if (!response.ok || !data.ok) {
    throw new Error(data.error || "Không thể tạo key.");
  }

  return data;
}

function formatExpiry(value) {
  if (!value) return "Theo lần kích hoạt đầu tiên";

  let date;

  if (typeof value === "number") {
    date = new Date(value < 1000000000000 ? value * 1000 : value);
  } else {
    date = new Date(value);
  }

  if (Number.isNaN(date.getTime())) {
    return "Theo lần kích hoạt đầu tiên";
  }

  return date.toLocaleString("vi-VN");
}

function showKey(data) {
  if (!data || !data.key) {
    throw new Error("Máy chủ không trả về key.");
  }

  currentKey = data.key;

  $("keyValue").textContent = data.key;
  $("planValue").textContent = `${data.planHours || 24} giờ`;
  $("expiresValue").textContent = formatExpiry(data.expiresAt);
  $("statusBadge").textContent = String(data.status || "ACTIVE").toUpperCase();

  $("result").classList.remove("hidden");
  $("result").scrollIntoView({
    behavior: "smooth",
    block: "center"
  });
}

async function generateKey() {
  const button = $("generateBtn");

  try {
    button.disabled = true;
    button.innerHTML = "<span>⌛</span><span>Generating...</span>";

    setMessage("Đang tạo key 24 giờ...");

    const result = await api("/api/demo-key", {
      planHours: 24
    });

    showKey(result.data);
    setMessage("Tạo key thành công.", "success");
  } catch (error) {
    setMessage(error.message || "Không thể tạo key.", "error");
  } finally {
    button.disabled = false;
    button.innerHTML = "<span>⇥</span><span>Generate</span>";
  }
}

async function copyKey() {
  if (!currentKey) return;

  const button = $("copyBtn");

  try {
    await navigator.clipboard.writeText(currentKey);
  } catch {
    const temporaryInput = document.createElement("textarea");

    temporaryInput.value = currentKey;
    temporaryInput.style.position = "fixed";
    temporaryInput.style.opacity = "0";

    document.body.appendChild(temporaryInput);
    temporaryInput.select();
    document.execCommand("copy");
    temporaryInput.remove();
  }

  button.textContent = "Đã sao chép ✓";

  setTimeout(() => {
    button.textContent = "Sao chép key";
  }, 1500);
}

$("generateBtn").addEventListener("click", generateKey);
$("copyBtn").addEventListener("click", copyKey);

$("closeWelcome").addEventListener("click", () => {
  document.querySelector(".welcome-card").classList.add("hidden");
});
