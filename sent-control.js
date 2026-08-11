(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const loginCard = $("loginCard");
  const dashboard = $("dashboard");
  const tokenInput = $("adminToken");

  const loginMessage = $("loginMessage");
  const createMessage = $("createMessage");
  const freeCreateMessage = $("freeCreateMessage");
  const revokeMessage = $("revokeMessage");
  const statsMessage = $("statsMessage");
  const vipStatsMessage = $("vipStatsMessage");

  const resultList = $("resultList");
  const emptyResult = $("emptyResult");
  const copyAllBtn = $("copyAllBtn");

  const freeResultList = $("freeResultList");
  const freeEmptyResult = $("freeEmptyResult");
  const freeCopyAllBtn = $("freeCopyAllBtn");

  const recentList = $("recentList");
  const recentEmpty = $("recentEmpty");

  const vipRecentList = $("vipRecentList");
  const vipRecentEmpty = $("vipRecentEmpty");

  let adminToken = "";
  let createdKeys = [];
  let freeCreatedKeys = [];

  function setMessage(element, text, type = "") {
    if (!element) return;
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

  function formatPlan(hours) {
    const value = Number(hours) || 0;
    if (value > 0 && value % 24 === 0) {
      return `${value / 24} ngày`;
    }
    return `${value} giờ`;
  }

  function formatDeviceLimit(item) {
    const used = Number(item.devicesUsed) || 0;
    const limit = Number(item.maxDevices);
    return limit === 0
      ? `${used} / ∞ thiết bị`
      : `${used} / ${limit || 1} thiết bị`;
  }

  function statusLabel(status) {
    if (status === "revoked") return "Đã thu hồi";
    if (status === "expired") return "Hết hạn";
    return "Hoạt động";
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
        throw new Error(
          "Admin token không đúng hoặc chưa được cấu hình."
        );
      }

      throw new Error(
        data.error ||
        data.reason ||
        "Yêu cầu quản trị thất bại."
      );
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

  function renderTrend(stats) {
    const element = $("statTrend");
    if (!element) return;

    const trend = stats.todayVsYesterday || {};
    const difference = Number(trend.difference || 0);
    const percent = Number(trend.percentChange);

    if (difference === 0) {
      element.textContent = "Bằng hôm qua";
      return;
    }

    const sign = difference > 0 ? "+" : "";
    const percentageText = Number.isFinite(percent)
      ? ` (${sign}${percent}%)`
      : "";

    element.textContent =
      `${sign}${formatNumber(difference)} so với hôm qua${percentageText}`;
  }

  function makeRecentRow(item, { vip = false } = {}) {
    const row = document.createElement("div");
    row.className = "recent-row";

    const keyWrap = document.createElement("div");
    keyWrap.className = "recent-key";

    const code = document.createElement("code");
    code.textContent = item.key;
    keyWrap.append(code);

    if (vip && item.note) {
      const note = document.createElement("small");
      note.textContent = ` • ${item.note}`;
      note.style.color = "#8fa4c1";
      keyWrap.append(note);
    }

    const status = document.createElement("span");
    const safeStatus = [
      "active",
      "expired",
      "revoked"
    ].includes(item.status)
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

    row.append(
      keyWrap,
      status,
      devices,
      createdAt
    );

    return row;
  }

  function renderFreeStats(payload) {
    const stats = payload.stats || {};

    $("statCompleted").textContent =
      formatNumber(stats.completedSessions);
    $("statTotal").textContent =
      formatNumber(stats.total);
    $("statToday").textContent =
      formatNumber(stats.today);
    $("statYesterday").textContent =
      formatNumber(stats.yesterday);
    $("statActive").textContent =
      formatNumber(stats.active);
    $("statExpired").textContent =
      formatNumber(stats.expired);
    $("statRevoked").textContent =
      formatNumber(stats.revoked);

    renderTrend(stats);

    const recent = Array.isArray(payload.recent)
      ? payload.recent
      : [];

    recentList.replaceChildren();

    if (!recent.length) {
      recentEmpty.classList.remove("hidden");
      recentList.classList.add("hidden");
    } else {
      recentEmpty.classList.add("hidden");
      recentList.classList.remove("hidden");

      for (const item of recent) {
        recentList.append(
          makeRecentRow(item)
        );
      }
    }

    $("lastUpdated").textContent =
      `Cập nhật ${formatDate(
        payload.generatedAt ||
        new Date().toISOString()
      )}`;
  }

  function renderVipStats(payload) {
    const stats = payload.stats || {};

    $("vipStatTotal").textContent =
      formatNumber(stats.total);
    $("vipStatActive").textContent =
      formatNumber(stats.active);
    $("vipStatExpired").textContent =
      formatNumber(stats.expired);
    $("vipStatRevoked").textContent =
      formatNumber(stats.revoked);

    const recent = Array.isArray(payload.recent)
      ? payload.recent
      : [];

    vipRecentList.replaceChildren();

    if (!recent.length) {
      vipRecentEmpty.classList.remove("hidden");
      vipRecentList.classList.add("hidden");
    } else {
      vipRecentEmpty.classList.add("hidden");
      vipRecentList.classList.remove("hidden");

      for (const item of recent) {
        vipRecentList.append(
          makeRecentRow(item, { vip: true })
        );
      }
    }

    $("vipLastUpdated").textContent =
      `Cập nhật ${formatDate(
        payload.generatedAt ||
        new Date().toISOString()
      )}`;
  }

  async function loadAllStats({ quiet = false } = {}) {
    const button = $("refreshStatsBtn");

    button.disabled = true;
    button.classList.add("loading");

    if (!quiet) {
      setMessage(
        statsMessage,
        "Đang tải dữ liệu Free/Link4m..."
      );

      setMessage(
        vipStatsMessage,
        "Đang tải dữ liệu VIP..."
      );
    }

    try {
      const [freeData, vipData] = await Promise.all([
        adminApi("/api/admin/link4m-stats"),
        adminApi("/api/admin/vip/stats")
      ]);

      renderFreeStats(freeData);
      renderVipStats(vipData);

      setMessage(
        statsMessage,
        "Dữ liệu Free/Link4m đã cập nhật theo UTC+7.",
        "success"
      );

      setMessage(
        vipStatsMessage,
        "Dữ liệu key bán/VIP đã cập nhật.",
        "success"
      );

      return { freeData, vipData };
    } catch (error) {
      setMessage(
        statsMessage,
        error.message || "Không thể tải thống kê.",
        "error"
      );

      setMessage(
        vipStatsMessage,
        error.message || "Không thể tải thống kê VIP.",
        "error"
      );

      throw error;
    } finally {
      button.disabled = false;
      button.classList.remove("loading");
    }
  }

  function renderFreeCreatedKeys() {
    freeResultList.replaceChildren();

    if (!freeCreatedKeys.length) {
      freeEmptyResult.classList.remove("hidden");
      freeResultList.classList.add("hidden");
      freeCopyAllBtn.disabled = true;
      return;
    }

    freeEmptyResult.classList.add("hidden");
    freeResultList.classList.remove("hidden");
    freeCopyAllBtn.disabled = false;

    freeCreatedKeys.forEach(item => {
      const row = document.createElement("div");
      row.className = "key-item";

      const main = document.createElement("div");
      main.className = "key-main";

      const code = document.createElement("code");
      code.textContent = item.key;

      const meta = document.createElement("span");
      const limitText =
        Number(item.maxDevices) === 0
          ? "không giới hạn thiết bị"
          : `${Number(item.maxDevices) || 1} thiết bị`;

      meta.textContent =
        `FREE • ${formatPlan(item.planHours)} • ${limitText}`;

      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy-one";
      button.textContent = "Sao chép";

      button.addEventListener("click", async () => {
        await copyText(item.key);
        button.textContent = "Đã chép ✓";
        setTimeout(() => {
          button.textContent = "Sao chép";
        }, 1200);
      });

      main.append(code, meta);
      row.append(main, button);
      freeResultList.append(row);
    });
  }

  function renderCreatedKeys() {
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

    createdKeys.forEach(item => {
      const row = document.createElement("div");
      row.className = "key-item";

      const main = document.createElement("div");
      main.className = "key-main";

      const code = document.createElement("code");
      code.textContent = item.key;

      const meta = document.createElement("span");
      const limitText =
        Number(item.maxDevices) === 0
          ? "không giới hạn thiết bị"
          : `${Number(item.maxDevices) || 1} thiết bị`;

      const noteText =
        item.note
          ? ` • ${item.note}`
          : "";

      meta.textContent =
        `VIP • ${formatPlan(item.planHours)} • ${limitText}${noteText}`;

      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy-one";
      button.textContent = "Sao chép";

      button.addEventListener("click", async () => {
        await copyText(item.key);
        button.textContent = "Đã chép ✓";

        setTimeout(() => {
          button.textContent = "Sao chép";
        }, 1200);
      });

      main.append(code, meta);
      row.append(main, button);
      resultList.append(row);
    });
  }

  async function loginWithToken(value) {
    adminToken = value;

    setMessage(
      loginMessage,
      "Đang xác thực token..."
    );

    try {
      const data = await loadAllStats({
        quiet: true
      });

      if ($("rememberSession").checked) {
        sessionStorage.setItem(
          "sent_admin_token",
          adminToken
        );
      } else {
        sessionStorage.removeItem(
          "sent_admin_token"
        );
      }

      showDashboard();
      setMessage(loginMessage, "");

      setMessage(
        statsMessage,
        "Đã kết nối dữ liệu Free/Link4m.",
        "success"
      );

      setMessage(
        vipStatsMessage,
        "Đã kết nối dữ liệu VIP.",
        "success"
      );

      return data;
    } catch (error) {
      adminToken = "";

      sessionStorage.removeItem(
        "sent_admin_token"
      );

      showLogin();

      setMessage(
        loginMessage,
        error.message,
        "error"
      );

      throw error;
    }
  }

  $("toggleToken").addEventListener("click", () => {
    const hidden = tokenInput.type === "password";
    tokenInput.type = hidden ? "text" : "password";
    $("toggleToken").textContent =
      hidden ? "Ẩn" : "Hiện";
  });

  $("loginBtn").addEventListener("click", async () => {
    const button = $("loginBtn");
    const value = tokenInput.value.trim();

    if (!value) {
      setMessage(
        loginMessage,
        "Hãy nhập ADMIN_TOKEN.",
        "error"
      );
      return;
    }

    button.disabled = true;

    try {
      await loginWithToken(value);
    } catch {
      // Lỗi đã hiển thị.
    } finally {
      button.disabled = false;
    }
  });

  $("refreshStatsBtn").addEventListener("click", async () => {
    try {
      await loadAllStats();
    } catch (error) {
      if (/token/i.test(error.message)) {
        sessionStorage.removeItem(
          "sent_admin_token"
        );
        showLogin();
      }
    }
  });

  $("freeCreateBtn").addEventListener("click", async () => {
    const button = $("freeCreateBtn");

    const planHours =
      Number($("freePlanHours").value);
    const maxDevices =
      Number($("freeMaxDevices").value);

    const count = Math.max(
      1,
      Math.min(
        20,
        Number($("freeKeyCount").value) || 1
      )
    );

    button.disabled = true;

    setMessage(
      freeCreateMessage,
      `Đang tạo ${count} key Free...`
    );

    try {
      const newItems = [];

      for (let index = 0; index < count; index += 1) {
        const result = await adminApi(
          "/api/admin/free/create",
          {
            planHours,
            maxDevices
          }
        );

        newItems.push(result.data);
      }

      freeCreatedKeys = [
        ...newItems,
        ...freeCreatedKeys
      ];

      renderFreeCreatedKeys();

      setMessage(
        freeCreateMessage,
        `Đã tạo thành công ${newItems.length} key Free. Key Admin Free không tính vào thống kê Link4m.`,
        "success"
      );
    } catch (error) {
      setMessage(
        freeCreateMessage,
        error.message || "Không thể tạo key Free.",
        "error"
      );
    } finally {
      button.disabled = false;
    }
  });

  freeCopyAllBtn.addEventListener("click", async () => {
    if (!freeCreatedKeys.length) return;

    await copyText(
      freeCreatedKeys
        .map(item => item.key)
        .join("\n")
    );

    freeCopyAllBtn.textContent = "Đã sao chép ✓";

    setTimeout(() => {
      freeCopyAllBtn.textContent = "Sao chép tất cả";
    }, 1300);
  });

  $("createBtn").addEventListener("click", async () => {
    const button = $("createBtn");

    const planHours =
      Number($("planHours").value);
    const maxDevices =
      Number($("maxDevices").value);
    const note =
      $("vipNote").value.trim();

    const count = Math.max(
      1,
      Math.min(
        20,
        Number($("keyCount").value) || 1
      )
    );

    button.disabled = true;

    setMessage(
      createMessage,
      `Đang tạo ${count} key bán/VIP...`
    );

    try {
      const newItems = [];

      for (let index = 0; index < count; index += 1) {
        const result = await adminApi(
          "/api/admin/vip/create",
          {
            planHours,
            maxDevices,
            note
          }
        );

        newItems.push(result.data);
      }

      createdKeys = [
        ...newItems,
        ...createdKeys
      ];

      renderCreatedKeys();

      setMessage(
        createMessage,
        `Đã tạo thành công ${newItems.length} key VIP.`,
        "success"
      );

      await loadAllStats({
        quiet: true
      }).catch(() => {});
    } catch (error) {
      setMessage(
        createMessage,
        error.message || "Không thể tạo key VIP.",
        "error"
      );
    } finally {
      button.disabled = false;
    }
  });

  copyAllBtn.addEventListener("click", async () => {
    if (!createdKeys.length) return;

    await copyText(
      createdKeys
        .map(item => item.key)
        .join("\n")
    );

    copyAllBtn.textContent =
      "Đã sao chép ✓";

    setTimeout(() => {
      copyAllBtn.textContent =
        "Sao chép tất cả";
    }, 1300);
  });

  $("revokeBtn").addEventListener("click", async () => {
    const button = $("revokeBtn");
    const key = cleanKey(
      $("revokeKey").value
    );

    if (!key) {
      setMessage(
        revokeMessage,
        "Hãy nhập key cần thu hồi.",
        "error"
      );
      return;
    }

    button.disabled = true;

    setMessage(
      revokeMessage,
      "Đang thu hồi key..."
    );

    try {
      const result = await adminApi(
        "/api/admin/revoke",
        { key }
      );

      if (!result.changed) {
        throw new Error(
          "Không tìm thấy key hoặc key đã bị thu hồi."
        );
      }

      createdKeys =
        createdKeys.filter(
          item => item.key !== key
        );

      renderCreatedKeys();
      $("revokeKey").value = "";

      setMessage(
        revokeMessage,
        "Đã thu hồi key thành công.",
        "success"
      );

      await loadAllStats({
        quiet: true
      }).catch(() => {});
    } catch (error) {
      setMessage(
        revokeMessage,
        error.message || "Không thể thu hồi key.",
        "error"
      );
    } finally {
      button.disabled = false;
    }
  });

  $("logoutBtn").addEventListener("click", () => {
    adminToken = "";
    createdKeys = [];
    freeCreatedKeys = [];

    sessionStorage.removeItem(
      "sent_admin_token"
    );

    tokenInput.value = "";
    renderCreatedKeys();
    renderFreeCreatedKeys();

    setMessage(createMessage, "");
    setMessage(freeCreateMessage, "");
    setMessage(revokeMessage, "");
    setMessage(statsMessage, "");
    setMessage(vipStatsMessage, "");

    showLogin();
  });

  tokenInput.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      $("loginBtn").click();
    }
  });

  const savedToken =
    sessionStorage.getItem(
      "sent_admin_token"
    );

  if (savedToken) {
    tokenInput.value = savedToken;

    loginWithToken(
      savedToken
    ).catch(() => {});
  }

  renderCreatedKeys();
  renderFreeCreatedKeys();
})();
