(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const loginCard = $("loginCard");
  const dashboard = $("dashboard");
  const tokenInput = $("adminToken");
  const loginMessage = $("loginMessage");
  const createMessage = $("createMessage");
  const revokeMessage = $("revokeMessage");
  const resultList = $("resultList");
  const emptyResult = $("emptyResult");
  const copyAllBtn = $("copyAllBtn");

  let adminToken = "";
  let createdKeys = [];

  function setMessage(element, text, type = "") {
    element.textContent = text;
    element.className = `message ${type}`.trim();
  }

  function cleanKey(value) {
    return String(value || "")
      .trim()
      .toUpperCase()
      .replace(/\s+/g, "");
  }

  /*
   * Database/API vẫn dùng SENT làm định dạng chuẩn.
   * Trang admin có thể hiển thị và sao chép alias SUNNY.
   */
  function toCanonicalSentKey(value) {
    let key = cleanKey(value);

    while (key.startsWith("SUNNY-")) {
      key = key.slice("SUNNY-".length);
    }

    if (
      /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(key)
    ) {
      return `SENT-${key}`;
    }

    return key;
  }

  function formatAdminKey(value, format) {
    const canonical = toCanonicalSentKey(value);

    if (
      format === "SUNNY" &&
      canonical.startsWith("SENT-")
    ) {
      return `SUNNY-${canonical.slice("SENT-".length)}`;
    }

    return canonical;
  }

  function visibleKey(item) {
    return item.displayKey || item.key;
  }

  async function adminApi(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "accept": "application/json",
        "authorization": `Bearer ${adminToken}`
      },
      body: JSON.stringify(body || {})
    });

    const data = await response.json().catch(() => ({
      ok: false,
      error: "Máy chủ trả về dữ liệu không hợp lệ."
    }));

    if (!response.ok || !data.ok) {
      if (response.status === 401) {
        throw new Error("Admin token không đúng hoặc chưa được cấu hình.");
      }
      throw new Error(data.error || "Yêu cầu quản trị thất bại.");
    }

    return data;
  }

  function showDashboard() {
    loginCard.classList.add("hidden");
    dashboard.classList.remove("hidden");
  }

  function showLogin() {
    dashboard.classList.add("hidden");
    loginCard.classList.remove("hidden");
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
  }

  function renderKeys() {
    resultList.replaceChildren();

    if (!createdKeys.length) {
      emptyResult.classList.remove("hidden");
      resultList.classList.add("hidden");
      copyAllBtn.disabled = true;
      return;
    }

    emptyResult.classList.add("hidden");
    resultList.classList.remove("hidden");
    copyAllBtn.disabled = false;

    createdKeys.forEach((item, index) => {
      const row = document.createElement("div");
      row.className = "key-item";

      const main = document.createElement("div");
      main.className = "key-main";

      const code = document.createElement("code");
      code.textContent = visibleKey(item);

      const meta = document.createElement("span");
      meta.textContent = `${item.planHours || 24} giờ • ${String(item.status || "ACTIVE").toUpperCase()}`;

      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy-one";
      button.textContent = "Sao chép";
      button.addEventListener("click", async () => {
        await copyText(visibleKey(item));
        button.textContent = "Đã chép ✓";
        setTimeout(() => button.textContent = "Sao chép", 1200);
      });

      main.append(code, meta);
      row.append(main, button);
      resultList.append(row);
    });
  }

  $("toggleToken").addEventListener("click", () => {
    const hidden = tokenInput.type === "password";
    tokenInput.type = hidden ? "text" : "password";
    $("toggleToken").textContent = hidden ? "Ẩn" : "Hiện";
  });

  $("loginBtn").addEventListener("click", async () => {
    const value = tokenInput.value.trim();
    if (!value) {
      setMessage(loginMessage, "Hãy nhập ADMIN_TOKEN.", "error");
      return;
    }

    adminToken = value;
    setMessage(loginMessage, "Đang kiểm tra token...");

    try {
      // Gọi thử endpoint với dữ liệu không hợp lệ nhưng không tạo key:
      // Endpoint hiện tại không có API ping admin, nên chỉ lưu token và kiểm tra lúc tạo.
      if ($("rememberSession").checked) {
        sessionStorage.setItem("sent_admin_token", adminToken);
      }
      showDashboard();
      setMessage(loginMessage, "");
    } catch (error) {
      adminToken = "";
      setMessage(loginMessage, error.message, "error");
    }
  });

  $("createBtn").addEventListener("click", async () => {
    const button = $("createBtn");
    const planHours = Number($("planHours").value);
    const keyFormat = $("keyFormat").value === "SUNNY"
      ? "SUNNY"
      : "SENT";
    const count = Math.max(1, Math.min(20, Number($("keyCount").value) || 1));

    button.disabled = true;
    setMessage(createMessage, `Đang tạo ${count} key...`);

    try {
      const newItems = [];

      // API hiện tại tạo một key mỗi lần. Gọi tuần tự để tránh dồn quá nhiều request.
      for (let index = 0; index < count; index += 1) {
        const result = await adminApi("/api/admin/create-key", { planHours });

        newItems.push({
          ...result.data,
          canonicalKey: toCanonicalSentKey(result.data.key),
          displayKey: formatAdminKey(result.data.key, keyFormat)
        });
      }

      createdKeys = [...newItems, ...createdKeys];
      renderKeys();
      setMessage(createMessage, `Đã tạo thành công ${newItems.length} key.`, "success");
    } catch (error) {
      if (/token/i.test(error.message)) {
        sessionStorage.removeItem("sent_admin_token");
      }
      setMessage(createMessage, error.message || "Không thể tạo key.", "error");
    } finally {
      button.disabled = false;
    }
  });

  copyAllBtn.addEventListener("click", async () => {
    if (!createdKeys.length) return;
    await copyText(createdKeys.map(visibleKey).join("\n"));
    copyAllBtn.textContent = "Đã sao chép ✓";
    setTimeout(() => copyAllBtn.textContent = "Sao chép tất cả", 1300);
  });

  $("revokeBtn").addEventListener("click", async () => {
    const button = $("revokeBtn");
    const key = cleanKey($("revokeKey").value);

    if (!key) {
      setMessage(revokeMessage, "Hãy nhập key cần thu hồi.", "error");
      return;
    }

    button.disabled = true;
    setMessage(revokeMessage, "Đang thu hồi key...");

    try {
      const result = await adminApi("/api/admin/revoke", { key });
      if (!result.changed) {
        throw new Error("Không tìm thấy key hoặc key đã bị thu hồi.");
      }

      const canonicalRevoked = toCanonicalSentKey(key);

      createdKeys = createdKeys.filter(
        (item) =>
          toCanonicalSentKey(
            item.canonicalKey || item.key
          ) !== canonicalRevoked
      );
      renderKeys();
      $("revokeKey").value = "";
      setMessage(revokeMessage, "Đã thu hồi key thành công.", "success");
    } catch (error) {
      setMessage(revokeMessage, error.message || "Không thể thu hồi key.", "error");
    } finally {
      button.disabled = false;
    }
  });

  $("logoutBtn").addEventListener("click", () => {
    adminToken = "";
    createdKeys = [];
    sessionStorage.removeItem("sent_admin_token");
    tokenInput.value = "";
    renderKeys();
    setMessage(createMessage, "");
    setMessage(revokeMessage, "");
    showLogin();
  });

  tokenInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("loginBtn").click();
  });

  const savedToken = sessionStorage.getItem("sent_admin_token");
  if (savedToken) {
    adminToken = savedToken;
    tokenInput.value = savedToken;
    showDashboard();
  }

  renderKeys();
})();
                                 
