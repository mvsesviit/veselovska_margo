"use strict";

const result = document.querySelector("#result");
const stateBadge = document.querySelector("#state");
const profileBox = document.querySelector("#profile");

// Усі запити йдуть лише на цей самий origin, cookie додає браузер.
async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  return fetch(url, { ...options, credentials: "same-origin" });
}

function showResult(text) {
  result.textContent = text;
}

function showState(state) {
  const labels = {
    "signed-in": "Сеанс активний",
    "anonymous": "Не ввійшли",
    "unknown": "Стан невідомий"
  };
  stateBadge.dataset.state = state;
  stateBadge.textContent = labels[state];
}

function clearProfile() {
  profileBox.hidden = true;
  document.querySelector("#profile-id").textContent = "";
  document.querySelector("#profile-userName").textContent = "";
  document.querySelector("#profile-displayName").textContent = "";
}

// Показуємо лише безпечні поля й лише через textContent.
function showProfile(profile) {
  document.querySelector("#profile-id").textContent = String(profile.id ?? "");
  document.querySelector("#profile-userName").textContent = String(profile.userName ?? "");
  document.querySelector("#profile-displayName").textContent = String(profile.displayName ?? "");
  profileBox.hidden = false;
}

// Лише статус і назви полів помилок, без тіла запиту (там може бути пароль).
async function describeProblem(response) {
  const type = response.headers.get("Content-Type") ?? "";
  if (!type.includes("json")) return "";
  try {
    const body = await response.json();
    if (body.errors) {
      return " Поля з помилками: " + Object.entries(body.errors)
        .map(([field, messages]) => `${field} — ${messages.join(" ")}`).join("; ");
    }
    return body.detail ? " " + body.detail : "";
  } catch {
    return "";
  }
}

async function refreshSessionState() {
  try {
    const response = await apiFetch("/api/auth/session-check");
    if (response.status === 204) {
      showState("signed-in");
    } else if (response.status === 401) {
      showState("anonymous");
      clearProfile();
    } else {
      showState("unknown");
    }
  } catch {
    showState("unknown");
  }
}

async function loadProfile() {
  const response = await apiFetch("/api/me");
  const type = response.headers.get("Content-Type") ?? "";
  if (response.ok && type.includes("application/json")) {
    showProfile(await response.json());
    showResult(`Профіль: ${response.status}`);
  } else if (response.status === 401) {
    clearProfile();
    showState("anonymous");
    showResult("Профіль: 401 (не ввійшли)");
  } else {
    clearProfile();
    showResult(`Профіль: помилка ${response.status}`);
  }
}

// 1. Реєстрація: 201 без автоматичного входу.
document.querySelector("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  const response = await apiFetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      userName: data.userName,
      email: data.email,
      displayName: data.displayName,
      password: data.password
    })
  });
  form.elements.password.value = "";
  if (response.status === 201) {
    showResult("Реєстрація: 201. Тепер увійдіть.");
  } else {
    showResult(`Реєстрація: ${response.status}.${await describeProblem(response)}`);
  }
});

// 2. Вхід: після успіху одразу читаємо профіль.
document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  const response = await apiFetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userName: data.userName, password: data.password })
  });
  form.elements.password.value = "";
  showResult(`Login: ${response.status}`);
  await refreshSessionState();
  if (response.status === 204) {
    await loadProfile();
  } else {
    clearProfile();
  }
});

// 3. Профіль.
document.querySelector("#me").addEventListener("click", async () => {
  await loadProfile();
});

// 4. Створення інциденту: у JSON немає жодних полів власника, статусу чи id.
document.querySelector("#incident").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  const response = await apiFetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      title: data.title,
      description: data.description,
      severity: data.severity,
      occurredAtUtc: new Date(data.occurredAt).toISOString()
    })
  });
  if (response.status === 201) {
    const created = await response.json();
    showResult(`Створення: 201. id=${created.id}, статус=${created.status}`);
  } else if (response.status === 401) {
    showState("anonymous");
    showResult("Створення: 401 (потрібен вхід)");
  } else {
    showResult(`Створення: ${response.status}.${await describeProblem(response)}`);
  }
});

// 5. Вихід: серверний sign-out, потім очищення інтерфейсу й повторна перевірка.
document.querySelector("#logout").addEventListener("click", async () => {
  const response = await apiFetch("/api/auth/logout", { method: "POST" });
  clearProfile();
  document.querySelector("#incident").reset();
  setDefaultDate();
  await refreshSessionState();
  const check = await apiFetch("/api/me");
  showResult(`Logout: ${response.status}. Повторний /api/me: ${check.status}`);
});

// Зручне значення за замовчуванням: година тому, у локальному форматі datetime-local.
function setDefaultDate() {
  const d = new Date(Date.now() - 60 * 60 * 1000);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  document.querySelector("#incident").elements.occurredAt.value = d.toISOString().slice(0, 16);
}

setDefaultDate();
refreshSessionState();