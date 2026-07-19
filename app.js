const $ = (id) => document.getElementById(id);
let currentKey = "";

function setMessage(element, text, type = "") {
  element.textContent = text;
  element.className = `message ${type}`.trim();
}

async function api(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const data = await response.json().catch(() => ({ ok: false, error: "Phản hồi máy chủ không hợp lệ." }));
  if (!response.ok || !data.ok) throw new Error(data.error || "Yêu cầu thất bại.");
  return data;
}

function getDeviceId() {
  const value = $("deviceId").value.trim();
  if (value.length < 6) throw new Error("Hãy nhập Device ID có ít nhất 6 ký tự.");
  localStorage.setItem("sent_device_id", value);
  return value;
}

function showKey(data) {
  currentKey = data.key;
  $("keyValue").textContent = data.key;
  $("verifyKey").value = data.key;
  $("planValue").textContent = `${data.planHours} giờ`;
  $("expiresValue").textContent = new Date(data.expiresAt).toLocaleString("vi-VN");
  $("statusBadge").textContent = data.status.toUpperCase();
  $("result").classList.remove("hidden");
  $("result").scrollIntoView({ behavior: "smooth", block: "center" });
}

for (const button of document.querySelectorAll(".plan")) {
  button.addEventListener("click", async () => {
    try {
      getDeviceId();
      setMessage($("message"), "Đang tạo key…");
      button.disabled = true;
      const result = await api("/api/demo-key", { planHours: Number(button.dataset.hours) });
      showKey(result.data);
      setMessage($("message"), "Đã tạo key. Hãy kích hoạt trên thiết bị này.", "success");
    } catch (error) {
      setMessage($("message"), error.message, "error");
    } finally {
      button.disabled = false;
    }
  });
}

$("copyBtn").addEventListener("click", async () => {
  if (!currentKey) return;
  await navigator.clipboard.writeText(currentKey);
  $("copyBtn").textContent = "ĐÃ CHÉP";
  setTimeout(() => $("copyBtn").textContent = "SAO CHÉP", 1200);
});

$("claimBtn").addEventListener("click", async () => {
  try {
    const deviceId = getDeviceId();
    if (!currentKey) throw new Error("Chưa có key để kích hoạt.");
    setMessage($("message"), "Đang kích hoạt…");
    const result = await api("/api/claim", { key: currentKey, deviceId });
    showKey(result.data);
    setMessage($("message"), "Kích hoạt thành công. Key đã gắn với thiết bị này.", "success");
  } catch (error) {
    setMessage($("message"), error.message, "error");
  }
});

$("verifyBtn").addEventListener("click", async () => {
  try {
    const deviceId = getDeviceId();
    const key = $("verifyKey").value.trim();
    setMessage($("verifyMessage"), "Đang kiểm tra…");
    const result = await api("/api/verify", { key, deviceId });
    if (result.valid) {
      setMessage($("verifyMessage"), `Key hợp lệ, còn ${result.data.remainingSeconds} giây.`, "success");
    } else {
      setMessage($("verifyMessage"), `Key không hợp lệ: ${result.reason}.`, "error");
    }
  } catch (error) {
    setMessage($("verifyMessage"), error.message, "error");
  }
});

const savedDevice = localStorage.getItem("sent_device_id");
if (savedDevice) $("deviceId").value = savedDevice;
