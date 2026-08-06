(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const loginCard = $("loginCard");
  const dashboard = $("dashboard");
  const tokenInput = $("adminToken");
  const loginMessage = $("loginMessage");
  const createMessage = $("createMessage");
  const revokeMessage = $("revokeMessage");
  const statsMessage = $("statsMessage");
  const resultList = $("resultList");
  const emptyResult = $("emptyResult");
  const copyAllBtn = $("copyAllBtn");
  const recentList = $("recentList");
  const recentEmpty = $("recentEmpty");

  let adminToken = "";
  let createdKeys = [];

  function setMessage(element, text, type = "") {
    element.textContent = text;
    element.className = `message ${type}`.trim();
  }

  function cleanKey(value) {
    return String(value || "").trim().toUpperCase();
  }

  function formatNumber(value) {
    return new Intl.NumberFormat("vi-VN").format(Number(value) || 0);
  }

  function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Không rõ";

    return new Intl.DateTimeFormat("vi-VN", {
      timeZone: "Asia/Ho_Chi_Minh",
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    }).format(date);
  }

  function formatDeviceLimit(item) {
    const used = Number(item.devicesUsed) || 0;
    const limit = Number(item.maxDevices);
    return limit === 0 ? `${used} / ∞ thiết bị` : `${used} / ${limit || 1} thiết bị`;
  }

  async function adminApi(path, body = {}) {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "accept": "application/json",
        "authorization": `Bearer ${adminToken}`
      },
      body: JSON.stringify(body)
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

  function statusLabel(status) {
    if (status === "revoked") return "Đã thu hồi";
    if (status === "expired") return "Hết hạn";
    return "Hoạt động";
  }

  function renderStats(payload) {
    const stats = payload.stats || {};
    $("statTotal").textContent = formatNumber(stats.total);
    $("statToday").textContent = formatNumber(stats.today);
    $("statActive").textContent = formatNumber(stats.active);
    $("statExpired").textContent = formatNumber(stats.expired);

    const recent = Array.isArray(payload.recent) ? payload.recent : [];
    recentList.replaceChildren();

    if (!recent.length) {
      recentEmpty.classList.remove("hidden");
      recentList.classList.add("hidden");
    } else {
      recentEmpty.classList.add("hidden");
      recentList.classList.remove("hidden");

      for (const item of recent) {
        const row = document.createElement("div");
        row.className = "recent-row";

        const keyWrap = document.createElement("div");
        keyWrap.className = "recent-key";
        const code = document.createElement("code");
        code.textContent = item.key;
        keyWrap.append(code);

        const status = document.createElement("span");
        const safeStatus = ["active", "expired", "revoked"].includes(item.status)
          ? item.status
          : "active";
        status.className = `status-pill status-${safeStatus}`;
        status.textContent = statusLabel(safeStatus);

        const devices = document.createElement("span");
        devices.className = "device-count";
        devices.textContent = formatDeviceLimit(item);

        const createdAt = document.createElement("time");
        createdAt.className = "created-time";
        createdAt.dateTime = item.createdAt || "";
        createdAt.textContent = formatDate(item.createdAt);

        row.append(keyWrap, status, devices, createdAt);
        recentList.append(row);
      }
    }

    $("lastUpdated").textContent = `Cập nhật ${formatDate(payload.generatedAt || new Date().toISOString())}`;
  }

  async function loadStats({ quiet = false } = {}) {
    const button = $("refreshStatsBtn");
    button.disabled = true;
    button.classList.add("loading");
    if (!quiet) setMessage(statsMessage, "Đang tải dữ liệu Link4m...");

    try {
      const data = await adminApi("/api/admin/link4m-stats");
      renderStats(data);
      setMessage(statsMessage, "Dữ liệu Link4m đã được cập nhật.", "success");
      return data;
    } catch (error) {
      setMessage(statsMessage, error.message || "Không thể tải thống kê Link4m.", "error");
      throw error;
    } finally {
      button.disabled = false;
      button.classList.remove("loading");
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

    createdKeys.forEach((item) => {
      const row = document.createElement("div");
      row.className = "key-item";

      const main = document.createElement("div");
      main.className = "key-main";

      const code = document.createElement("code");
      code.textContent = item.key;

      const meta = document.createElement("span");
      const limitText = Number(item.maxDevices) === 0
        ? "không giới hạn thiết bị"
        : `${Number(item.maxDevices) || 1} thiết bị`;
      meta.textContent = `${item.planHours || 24} giờ • ${limitText}`;

      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy-one";
      button.textContent = "Sao chép";
      button.addEventListener("click", async () => {
        await copyText(item.key);
        button.textContent = "Đã chép ✓";
        setTimeout(() => { button.textContent = "Sao chép"; }, 1200);
      });

      main.append(code, meta);
      row.append(main, button);
      resultList.append(row);
    });
  }

  async function loginWithToken(value) {
    adminToken = value;
    setMessage(loginMessage, "Đang xác thực token...");

    try {
      const data = await adminApi("/api/admin/link4m-stats");
      if ($("rememberSession").checked) {
        sessionStorage.setItem("sent_admin_token", adminToken);
      } else {
        sessionStorage.removeItem("sent_admin_token");
      }
      renderStats(data);
      showDashboard();
      setMessage(loginMessage, "");
      setMessage(statsMessage, "Đã kết nối với dữ liệu Link4m.", "success");
    } catch (error) {
      adminToken = "";
      sessionStorage.removeItem("sent_admin_token");
      showLogin();
      setMessage(loginMessage, error.message, "error");
      throw error;
    }
  }

  $("toggleToken").addEventListener("click", () => {
    const hidden = tokenInput.type === "password";
    tokenInput.type = hidden ? "text" : "password";
    $("toggleToken").textContent = hidden ? "Ẩn" : "Hiện";
  });

  $("loginBtn").addEventListener("click", async () => {
    const button = $("loginBtn");
    const value = tokenInput.value.trim();

    if (!value) {
      setMessage(loginMessage, "Hãy nhập ADMIN_TOKEN.", "error");
      return;
    }

    button.disabled = true;
    try {
      await loginWithToken(value);
    } catch {
      // Lỗi đã được hiển thị trong loginWithToken.
    } finally {
      button.disabled = false;
    }
  });

  $("refreshStatsBtn").addEventListener("click", async () => {
    try {
      await loadStats();
    } catch (error) {
      if (/token/i.test(error.message)) {
        sessionStorage.removeItem("sent_admin_token");
        showLogin();
      }
    }
  });

  $("createBtn").addEventListener("click", async () => {
    const button = $("createBtn");
    const planHours = Number($("planHours").value);
    const maxDevices = Number($("maxDevices").value);
    const count = Math.max(1, Math.min(20, Number($("keyCount").value) || 1));

    button.disabled = true;
    setMessage(createMessage, `Đang tạo ${count} key SENT...`);

    try {
      const newItems = [];

      for (let index = 0; index < count; index += 1) {
        const result = await adminApi("/api/admin/create-key", {
          planHours,
          maxDevices
        });
        newItems.push(result.data);
      }

      createdKeys = [...newItems, ...createdKeys];
      renderKeys();
      setMessage(createMessage, `Đã tạo thành công ${newItems.length} key Admin.`, "success");
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
    await copyText(createdKeys.map((item) => item.key).join("\n"));
    copyAllBtn.textContent = "Đã sao chép ✓";
    setTimeout(() => { copyAllBtn.textContent = "Sao chép tất cả"; }, 1300);
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

      createdKeys = createdKeys.filter((item) => item.key !== key);
      renderKeys();
      $("revokeKey").value = "";
      setMessage(revokeMessage, "Đã thu hồi key thành công.", "success");
      await loadStats({ quiet: true }).catch(() => {});
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
    setMessage(statsMessage, "");
    showLogin();
  });

  tokenInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("loginBtn").click();
  });

  const savedToken = sessionStorage.getItem("sent_admin_token");
  if (savedToken) {
    tokenInput.value = savedToken;
    loginWithToken(savedToken).catch(() => {});
  }

  renderKeys();
})();
