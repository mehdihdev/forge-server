import express from "express";
import session from "express-session";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();

const {
  SUPABASE_URL,
  SUPABASE_PUBLISHABLE_KEY,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  SESSION_SECRET = "dev-secret",
  PORT = 3000
} = process.env;

const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const apiKey = SUPABASE_SECRET_KEY || SUPABASE_PUBLISHABLE_KEY || "";

if (!SUPABASE_URL || !apiKey) {
  console.warn(
    "Missing SUPABASE_URL or SUPABASE_PUBLISHABLE_KEY / SUPABASE_SECRET_KEY in .env"
  );
}

const supabase = createClient(SUPABASE_URL || "", apiKey, {
  auth: { persistSession: false, detectSessionInUrl: false }
});

const supabaseAdmin = SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL || "", SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, detectSessionInUrl: false }
    })
  : null;
const GITHUB_TOKENS_TABLE = "github_tokens";

const createUserClient = async (sessionData) => {
  const client = createClient(SUPABASE_URL || "", apiKey, {
    auth: { persistSession: false, detectSessionInUrl: false }
  });

  if (sessionData?.access_token && sessionData?.refresh_token) {
    await client.auth.setSession({
      access_token: sessionData.access_token,
      refresh_token: sessionData.refresh_token
    });
  }

  return client;
};

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    }
  })
);

const layout = ({ title, body }) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="min-h-screen bg-slate-950 text-slate-100">
    ${body}
  </body>
</html>`;

const getDisplayName = (sessionData) => {
  if (!sessionData?.user) return "";
  return (
    sessionData?.profile?.first_name ||
    sessionData?.user?.user_metadata?.first_name ||
    sessionData?.user?.email?.split("@")[0] ||
    "Account"
  );
};

const requireAuth = (req, res) => {
  if (!req.session.user) {
    res.redirect("/login?message=Please%20log%20in%20to%20continue");
    return false;
  }
  return true;
};

const navbar = ({ sessionData, showAuth = true, showLinks = true }) => {
  const brandHref = sessionData?.user ? "/home" : "/";
  const displayName = getDisplayName(sessionData);

  const authSection = sessionData?.user
    ? `
      <details class="relative">
        <summary class="flex cursor-pointer items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-white/90 transition hover:border-white/30">
          <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
          ${displayName}
        </summary>
        <div class="absolute right-0 mt-3 w-44 rounded-2xl border border-white/10 bg-slate-950/95 p-2 text-sm shadow-xl">
          <a href="/home" class="block rounded-xl px-3 py-2 text-white/80 transition hover:bg-white/5 hover:text-white">User home</a>
          <a href="/settings" class="block rounded-xl px-3 py-2 text-white/80 transition hover:bg-white/5 hover:text-white">Settings</a>
          <form method="POST" action="/auth/logout">
            <button class="mt-1 w-full rounded-xl px-3 py-2 text-left text-white/80 transition hover:bg-white/5 hover:text-white">
              Log out
            </button>
          </form>
        </div>
      </details>
    `
    : showAuth
      ? `<a href="/login" class="rounded-full bg-white px-5 py-2 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">Login</a>`
      : "";

  const navLinks = showLinks
    ? `
      <nav class="hidden items-center gap-8 text-sm text-slate-300 md:flex">
        <a class="transition hover:text-white" href="#platform">Platform</a>
        <a class="transition hover:text-white" href="#research">Research</a>
        <a class="transition hover:text-white" href="#security">Security</a>
      </nav>
    `
    : "";

  return `
    <header class="sticky top-0 z-10 border-b border-white/10 bg-slate-950/70 backdrop-blur">
      <div class="mx-auto flex w-full max-w-6xl items-center justify-between px-6 py-4">
        <a href="${brandHref}" class="flex items-center gap-3">
          <div class="h-9 w-9 rounded-lg bg-gradient-to-br from-emerald-400 via-cyan-400 to-blue-500"></div>
          <span class="text-lg font-semibold tracking-tight">Solus Labs</span>
        </a>
        ${navLinks}
        ${authSection}
      </div>
    </header>
  `;
};

const formatRepoDate = (isoString) => {
  if (!isoString) return "Updated recently";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "Updated recently";
  return `Updated ${date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric"
  })}`;
};

const refreshGithubToken = async (refreshToken) => {
  if (!refreshToken || !GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) return null;

  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refreshToken
    })
  });

  if (!response.ok) {
    return null;
  }

  const data = await response.json();
  if (!data?.access_token) return null;

  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token || refreshToken
  };
};

const fetchGithubRepos = async (token) => {
  if (!token) return [];

  const response = await fetch(
    "https://api.github.com/user/repos?sort=updated&per_page=10",
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "solus-labs-app"
      }
    }
  );

  if (!response.ok) {
    const error = new Error(`GitHub API error (${response.status})`);
    error.status = response.status;
    throw error;
  }

  const repos = await response.json();
  return repos.map((repo) => ({
    name: repo.name,
    full_name: repo.full_name,
    owner: repo.owner?.login,
    description: repo.description || "No description provided.",
    updated: formatRepoDate(repo.updated_at),
    language: repo.language,
    stars: repo.stargazers_count || 0,
    forks: repo.forks_count || 0,
    private: repo.private
  }));
};

const fetchAllGithubRepos = async (token) => {
  if (!token) return [];
  const response = await fetch(
    "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "solus-labs-app"
      }
    }
  );

  if (!response.ok) {
    const error = new Error(`GitHub API error (${response.status})`);
    error.status = response.status;
    throw error;
  }

  const repos = await response.json();
  return repos
    .map((repo) => ({
      name: repo.name,
      owner: repo.owner?.login,
      full_name: repo.full_name,
      private: repo.private
    }))
    .sort((a, b) => a.full_name.localeCompare(b.full_name));
};

const fetchRepoDetails = async (token, owner, repo) => {
  const response = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "solus-labs-app"
    }
  });

  if (!response.ok) {
    const error = new Error(`GitHub API error (${response.status})`);
    error.status = response.status;
    throw error;
  }

  return response.json();
};

const fetchErrorsForge = async (token, owner, repo) => {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/.rde/errors.forge`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "solus-labs-app"
      }
    }
  );

  if (response.status === 404) {
    return { status: "missing" };
  }

  if (!response.ok) {
    const error = new Error(`GitHub API error (${response.status})`);
    error.status = response.status;
    throw error;
  }

  const data = await response.json();
  const content = data?.content
    ? Buffer.from(data.content, "base64").toString("utf-8")
    : "";

  if (!content.trim()) {
    return { status: "empty" };
  }

  try {
    const parsed = JSON.parse(content);
    const entries = Array.isArray(parsed?.entries) ? parsed.entries : [];
    return {
      status: entries.length ? "ok" : "empty",
      entries
    };
  } catch (err) {
    return { status: "invalid", raw: content };
  }
};

const resolveGithubIdentity = async (sessionData) => {
  if (!sessionData?.access_token) return false;
  try {
    const userClient = await createUserClient(sessionData);
    const { data, error } = await userClient.auth.getUser();
    if (error) return false;
    return (data.user?.identities || []).some((identity) => identity.provider === "github");
  } catch (err) {
    return false;
  }
};

const loadGithubTokens = async (userId) => {
  if (!supabaseAdmin || !userId) return null;
  const { data, error } = await supabaseAdmin
    .from(GITHUB_TOKENS_TABLE)
    .select("provider_token, provider_refresh_token")
    .eq("user_id", userId)
    .maybeSingle();
  if (error || !data) return null;
  return data;
};

const storeGithubTokens = async (userId, provider_token, provider_refresh_token) => {
  if (!supabaseAdmin || !userId || !provider_token) return;
  await supabaseAdmin.from(GITHUB_TOKENS_TABLE).upsert(
    {
      user_id: userId,
      provider_token,
      provider_refresh_token: provider_refresh_token || null,
      updated_at: new Date().toISOString()
    },
    { onConflict: "user_id" }
  );
};

const refreshTokenIfNeeded = async (sessionData) => {
  if (!sessionData?.githubToken || !sessionData?.user?.id) return null;

  const stored = await loadGithubTokens(sessionData.user.id);
  if (!stored?.provider_refresh_token) return null;

  const refreshed = await refreshGithubToken(stored.provider_refresh_token);
  if (!refreshed?.access_token) return null;

  await storeGithubTokens(
    sessionData.user.id,
    refreshed.access_token,
    refreshed.refresh_token
  );

  sessionData.githubToken = refreshed.access_token;
  return refreshed.access_token;
};

const clearGithubTokens = async (userId) => {
  if (!supabaseAdmin || !userId) return;
  await supabaseAdmin.from(GITHUB_TOKENS_TABLE).delete().eq("user_id", userId);
};

app.get("/", (req, res) => {
  const body = `
    ${navbar({ sessionData: req.session, showAuth: true, showLinks: true })}
    <main class="mx-auto w-full max-w-6xl px-6 py-16">
      <section class="grid gap-12 lg:grid-cols-[1.1fr_0.9fr]">
        <div>
          <p class="mb-4 text-sm uppercase tracking-[0.2em] text-emerald-300">Solus Labs</p>
          <h1 class="text-4xl font-semibold leading-tight text-white md:text-6xl">
            Build quieter, safer, and smarter systems for a resilient world.
          </h1>
          <p class="mt-6 text-lg text-slate-300">
            Solus Labs crafts adaptive infrastructure for teams operating in complex environments. We pair rigorous research with practical tooling to keep your operations trusted, verifiable, and ahead of the curve.
          </p>
          <div class="mt-8 flex flex-wrap items-center gap-4">
            <a href="/login" class="rounded-full bg-emerald-400 px-6 py-3 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">
              Get started
            </a>
            <button class="rounded-full border border-white/20 px-6 py-3 text-sm font-semibold text-white/80 transition hover:border-white hover:text-white">
              Request a demo
            </button>
          </div>
          <div class="mt-10 grid gap-4 text-sm text-slate-300 md:grid-cols-3">
            <div class="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p class="text-2xl font-semibold text-white">98%</p>
              <p>signal clarity across complex telemetry.</p>
            </div>
            <div class="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p class="text-2xl font-semibold text-white">24/7</p>
              <p>continuous compliance monitoring.</p>
            </div>
            <div class="rounded-2xl border border-white/10 bg-white/5 p-4">
              <p class="text-2xl font-semibold text-white">3x</p>
              <p>faster incident resolution.</p>
            </div>
          </div>
        </div>
        <div class="relative">
          <div class="absolute -inset-4 rounded-3xl bg-gradient-to-br from-emerald-500/40 via-cyan-500/10 to-blue-600/40 blur-2xl"></div>
          <div class="relative rounded-3xl border border-white/10 bg-white/5 p-8">
            <div class="flex items-center justify-between">
              <p class="text-sm text-emerald-200">Solus Navigator</p>
              <span class="rounded-full border border-white/10 px-3 py-1 text-xs text-white/70">Live</span>
            </div>
            <div class="mt-6 space-y-4">
              <div class="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                <p class="text-xs uppercase tracking-[0.25em] text-slate-400">Risk Posture</p>
                <p class="mt-2 text-2xl font-semibold text-white">Stable</p>
                <p class="mt-2 text-sm text-slate-400">Adaptive policies updated 6 minutes ago.</p>
              </div>
              <div class="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                <p class="text-xs uppercase tracking-[0.25em] text-slate-400">Signal Mesh</p>
                <p class="mt-2 text-2xl font-semibold text-white">12.4k streams</p>
                <p class="mt-2 text-sm text-slate-400">Realtime verification across 32 regions.</p>
              </div>
            </div>
            <div class="mt-6 rounded-2xl border border-white/10 bg-gradient-to-br from-slate-900 to-slate-950 p-4">
              <p class="text-xs uppercase tracking-[0.25em] text-slate-400">Next Action</p>
              <p class="mt-2 text-sm text-white">Review quantum-ready policy pack for finance cluster.</p>
            </div>
          </div>
        </div>
      </section>

      <section id="platform" class="mt-20 grid gap-6 md:grid-cols-3">
        <div class="rounded-3xl border border-white/10 bg-white/5 p-6">
          <h3 class="text-xl font-semibold text-white">Signal Intelligence</h3>
          <p class="mt-3 text-sm text-slate-300">Unify telemetry from edge, cloud, and human sources into a cohesive operating picture.</p>
        </div>
        <div class="rounded-3xl border border-white/10 bg-white/5 p-6">
          <h3 class="text-xl font-semibold text-white">Adaptive Controls</h3>
          <p class="mt-3 text-sm text-slate-300">Dynamic guardrails that adjust in real time to protect mission-critical flows.</p>
        </div>
        <div class="rounded-3xl border border-white/10 bg-white/5 p-6">
          <h3 class="text-xl font-semibold text-white">Assured Delivery</h3>
          <p class="mt-3 text-sm text-slate-300">Verified deployment pipelines with continuous compliance and rapid rollback.</p>
        </div>
      </section>

      <section id="research" class="mt-20 grid gap-6 rounded-3xl border border-white/10 bg-gradient-to-br from-emerald-500/10 via-slate-900 to-slate-950 p-10">
        <div>
          <h2 class="text-3xl font-semibold text-white">Research-led infrastructure</h2>
          <p class="mt-4 text-slate-300">
            Our research lab partners with operators, policy teams, and security experts to translate frontier advances into deployable tooling. From cryptographic assurance to autonomous recovery, Solus Labs is the quiet engine behind resilient systems.
          </p>
        </div>
        <div class="grid gap-6 md:grid-cols-2">
          <div class="rounded-2xl border border-white/10 bg-slate-950/60 p-6">
            <p class="text-sm text-emerald-200">Autonomous Recovery</p>
            <p class="mt-3 text-sm text-slate-300">Self-healing workflows for complex operational environments.</p>
          </div>
          <div class="rounded-2xl border border-white/10 bg-slate-950/60 p-6">
            <p class="text-sm text-emerald-200">Trustworthy AI</p>
            <p class="mt-3 text-sm text-slate-300">Verified reasoning layers that keep AI decisioning safe and auditable.</p>
          </div>
        </div>
      </section>

      <section id="security" class="mt-20 flex flex-col gap-6 rounded-3xl border border-white/10 bg-white/5 p-10 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 class="text-3xl font-semibold text-white">Security-first by design</h2>
          <p class="mt-4 text-slate-300">Zero trust, hardware-rooted identity, and constant validation for every workload.</p>
        </div>
        <a href="/login" class="rounded-full bg-white px-6 py-3 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">
          Secure access
        </a>
      </section>
    </main>
  `;

  res.send(layout({ title: "Solus Labs", body }));
});

app.get("/login", (req, res) => {
  const message = req.query.message ? String(req.query.message) : "";
  const body = `
    ${navbar({ sessionData: req.session, showAuth: false, showLinks: false })}
    <main class="mx-auto flex w-full max-w-3xl flex-col gap-10 px-6 py-16">
      <div>
        <p class="text-sm uppercase tracking-[0.2em] text-emerald-300">Secure access</p>
        <h1 class="mt-3 text-3xl font-semibold text-white">Sign in to Solus Labs</h1>
        <p class="mt-3 text-slate-300">Access your personalized homepage and workflows.</p>
        ${
          message
            ? `<div class="mt-6 rounded-2xl border border-emerald-400/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100">${message}</div>`
            : ""
        }
      </div>
      <form method="POST" action="/auth/login" class="rounded-3xl border border-white/10 bg-white/5 p-8">
        <label class="block text-sm text-slate-300">Email</label>
        <input name="email" type="email" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white placeholder:text-slate-500" placeholder="you@soluslabs.com" />
        <label class="mt-5 block text-sm text-slate-300">Password</label>
        <input name="password" type="password" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white placeholder:text-slate-500" placeholder="••••••••" />
        <button type="submit" class="mt-6 w-full rounded-full bg-white px-5 py-3 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">Login</button>
        <p class="mt-5 text-sm text-slate-400">
          New here? <a class="text-emerald-300 hover:text-emerald-200" href="/signup">Create an account</a>
        </p>
      </form>
    </main>
  `;

  res.send(layout({ title: "Login | Solus Labs", body }));
});

app.get("/signup", (req, res) => {
  const message = req.query.message ? String(req.query.message) : "";
  const body = `
    ${navbar({ sessionData: req.session, showAuth: false, showLinks: false })}
    <main class="mx-auto flex w-full max-w-3xl flex-col gap-10 px-6 py-16">
      <div>
        <p class="text-sm uppercase tracking-[0.2em] text-emerald-300">Create account</p>
        <h1 class="mt-3 text-3xl font-semibold text-white">Join Solus Labs</h1>
        <p class="mt-3 text-slate-300">Start with your first name, email, and a secure password.</p>
        ${
          message
            ? `<div class="mt-6 rounded-2xl border border-emerald-400/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100">${message}</div>`
            : ""
        }
      </div>
      <form method="POST" action="/auth/signup" class="rounded-3xl border border-white/10 bg-white/5 p-8">
        <label class="block text-sm text-slate-300">First name</label>
        <input name="first_name" type="text" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white placeholder:text-slate-500" placeholder="Ari" />
        <label class="mt-5 block text-sm text-slate-300">Email</label>
        <input name="email" type="email" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white placeholder:text-slate-500" placeholder="you@soluslabs.com" />
        <label class="mt-5 block text-sm text-slate-300">Password</label>
        <input name="password" type="password" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white placeholder:text-slate-500" placeholder="Create a strong password" />
        <button type="submit" class="mt-6 w-full rounded-full bg-emerald-400 px-5 py-3 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">Sign up</button>
        <p class="mt-5 text-sm text-slate-400">
          Already have an account? <a class="text-emerald-300 hover:text-emerald-200" href="/login">Log in</a>
        </p>
        <p class="mt-3 text-xs text-slate-500">If email confirmation is enabled, you will need to verify before logging in.</p>
      </form>
    </main>
  `;

  res.send(layout({ title: "Sign up | Solus Labs", body }));
});

app.get("/home", async (req, res) => {
  if (!requireAuth(req, res)) return;

  const firstName = getDisplayName(req.session);
  if (req.session.githubConnected === undefined) {
    req.session.githubConnected = await resolveGithubIdentity(req.session);
  }
  const githubConnected = Boolean(req.session.githubConnected);

  if (githubConnected && !req.session.githubToken) {
    const stored = await loadGithubTokens(req.session.user?.id);
    if (stored?.provider_token) {
      req.session.githubToken = stored.provider_token;
    }
  }

  if (githubConnected && !req.session.githubToken) {
    req.session.githubError =
      "GitHub is linked, but no provider token is available. Please reconnect GitHub to load repos.";
  }

  if (githubConnected && req.session.githubToken && !req.session.githubRepos) {
    try {
      req.session.githubRepos = await fetchGithubRepos(req.session.githubToken);
    } catch (err) {
      if (err?.status === 401) {
        const refreshed = await refreshTokenIfNeeded(req.session);
        if (refreshed) {
          try {
            req.session.githubRepos = await fetchGithubRepos(refreshed);
          } catch (retryErr) {
            req.session.githubRepos = [];
            req.session.githubError = `We connected to GitHub, but couldn't load repos yet (${retryErr.message}).`;
          }
        } else {
          req.session.githubRepos = [];
          req.session.githubError =
            "GitHub token expired. Please reconnect GitHub to continue.";
        }
      } else {
        req.session.githubRepos = [];
        req.session.githubError = err?.message
          ? `We connected to GitHub, but couldn't load repos yet (${err.message}).`
          : "We connected to GitHub, but couldn't load repos yet.";
      }
    }
  }

  const githubProjects = req.session.githubRepos || [];
  const githubError = req.session.githubError || "";
  let githubRepoOptions = req.session.githubRepoOptions || [];

  if (githubConnected && req.session.githubToken && !githubRepoOptions.length) {
    try {
      githubRepoOptions = await fetchAllGithubRepos(req.session.githubToken);
      req.session.githubRepoOptions = githubRepoOptions;
    } catch (err) {
      if (err?.status === 401) {
        const refreshed = await refreshTokenIfNeeded(req.session);
        if (refreshed) {
          try {
            githubRepoOptions = await fetchAllGithubRepos(refreshed);
            req.session.githubRepoOptions = githubRepoOptions;
          } catch (retryErr) {
            req.session.githubRepoOptions = [];
          }
        } else {
          req.session.githubRepoOptions = [];
        }
      } else {
        req.session.githubRepoOptions = [];
      }
    }
  }

  const body = `
    ${navbar({ sessionData: req.session, showAuth: false, showLinks: false })}
    <main class="mx-auto w-full max-w-5xl px-6 py-16">
      <div class="flex flex-col gap-8 rounded-3xl border border-white/10 bg-white/5 p-10">
        <div>
          <p class="text-sm uppercase tracking-[0.2em] text-emerald-300">Welcome back</p>
          <h1 class="mt-3 text-3xl font-semibold text-white">${firstName}</h1>
          <p class="mt-4 text-slate-300">Your Solus Labs workspace is ready. Connect GitHub to sync recent projects.</p>
        </div>

        <section class="rounded-3xl border border-white/10 bg-slate-950/70 p-8">
          <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <h2 class="text-xl font-semibold text-white">GitHub connection</h2>
              <p class="mt-2 text-sm text-slate-300">
                ${githubConnected ? "Connected and syncing your recent projects." : "Connect your GitHub account to surface your latest work."}
              </p>
            </div>
            ${
              githubConnected
                ? `<span class="rounded-full border border-emerald-400/40 bg-emerald-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-emerald-200">Connected</span>`
                : `<form method="POST" action="/auth/github/connect">
                    <button class="rounded-full bg-white px-5 py-2 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">Connect GitHub</button>
                  </form>`
            }
          </div>
          ${
            githubError
              ? `<div class="mt-4 rounded-2xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">${githubError}</div>`
              : ""
          }
          ${
            githubConnected && githubRepoOptions.length
              ? `
                <form method="GET" action="/repo/select" class="mt-6 grid gap-3 md:grid-cols-[1fr_auto]">
                  <div>
                    <label class="block text-xs uppercase tracking-[0.2em] text-slate-400">Jump to any repo</label>
                    <select name="full_name" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white">
                      <option value="" disabled selected>Select a repository</option>
                      ${githubRepoOptions
                        .map(
                          (repo) =>
                            `<option value="${repo.full_name}">${repo.full_name}${repo.private ? " (private)" : ""}</option>`
                        )
                        .join("")}
                    </select>
                  </div>
                  <div class="flex items-end">
                    <button class="w-full rounded-full bg-white px-5 py-3 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">Open</button>
                  </div>
                </form>
              `
              : ""
          }
          ${
            githubConnected && !req.session.githubToken
              ? `<div class="mt-4">
                  <form method="POST" action="/auth/github/connect">
                    <button class="rounded-full border border-white/20 px-5 py-2 text-sm font-semibold text-white/80 transition hover:border-white hover:text-white">Reconnect GitHub</button>
                  </form>
                </div>`
              : ""
          }
          ${
            githubConnected
              ? `
                <div class="mt-6 grid gap-4 md:grid-cols-3">
                  ${
                    githubProjects.length
                      ? githubProjects
                          .map(
                            (project) => `
                              <a href="/repo/${project.owner}/${project.name}" class="block rounded-2xl border border-white/10 bg-slate-950/80 p-4 transition hover:border-emerald-400/60 hover:bg-white/5">
                                <div class="flex items-center justify-between">
                                  <p class="text-sm font-semibold text-white">${project.name}</p>
                                  <span class="text-[11px] uppercase tracking-[0.2em] text-emerald-200">${project.private ? "Private" : "Public"}</span>
                                </div>
                                <p class="mt-2 text-xs text-slate-400">${project.updated}</p>
                                <p class="mt-3 text-sm text-slate-300">${project.description}</p>
                                <div class="mt-4 flex items-center gap-4 text-xs text-slate-400">
                                  <span>${project.language || "Unknown"}</span>
                                  <span>★ ${project.stars}</span>
                                  <span>⑂ ${project.forks}</span>
                                </div>
                              </a>
                            `
                          )
                          .join("")
                      : `<div class="rounded-2xl border border-white/10 bg-slate-950/80 p-4 text-sm text-slate-300">No repositories found yet.</div>`
                  }
                </div>
              `
              : ""
          }
        </section>
      </div>
    </main>
    <script>
      (function () {
        const hash = window.location.hash?.replace(/^#/, "");
        if (!hash) return;
        const params = new URLSearchParams(hash);
        if (params.get("access_token") || params.get("provider_token")) {
          fetch("/auth/github/callback/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              access_token: params.get("access_token"),
              refresh_token: params.get("refresh_token"),
              provider_token: params.get("provider_token"),
              provider_refresh_token: params.get("provider_refresh_token")
            })
          }).finally(() => {
            window.location.replace("/home");
          });
        } else if (params.get("error")) {
          fetch("/auth/github/callback/error", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              error: params.get("error"),
              error_description: params.get("error_description")
            })
          }).finally(() => {
            window.location.replace("/home");
          });
        }
      })();
    </script>
  `;

  res.send(layout({ title: "Home | Solus Labs", body }));
});

app.get("/settings", (req, res) => {
  if (!requireAuth(req, res)) return;

  const message = req.query.message ? String(req.query.message) : "";
  const firstName = getDisplayName(req.session);
  const githubConnected = Boolean(req.session.githubConnected);

  const body = `
    ${navbar({ sessionData: req.session, showAuth: false, showLinks: false })}
    <main class="mx-auto w-full max-w-4xl px-6 py-16">
      <div class="flex flex-col gap-8 rounded-3xl border border-white/10 bg-white/5 p-10">
        <div>
          <p class="text-sm uppercase tracking-[0.2em] text-emerald-300">Settings</p>
          <h1 class="mt-3 text-3xl font-semibold text-white">Account settings</h1>
          <p class="mt-3 text-slate-300">Manage your profile, security, and integrations.</p>
          ${
            message
              ? `<div class="mt-6 rounded-2xl border border-emerald-400/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100">${message}</div>`
              : ""
          }
        </div>

        <section class="rounded-3xl border border-white/10 bg-slate-950/70 p-8">
          <h2 class="text-xl font-semibold text-white">Profile</h2>
          <form method="POST" action="/settings/profile" class="mt-6 grid gap-4 md:grid-cols-[1fr_auto]">
            <div>
              <label class="block text-sm text-slate-300">First name</label>
              <input name="first_name" type="text" required value="${firstName}" class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white placeholder:text-slate-500" />
            </div>
            <div class="flex items-end">
              <button class="w-full rounded-full bg-white px-5 py-3 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">Save</button>
            </div>
          </form>
        </section>

        <section class="rounded-3xl border border-white/10 bg-slate-950/70 p-8">
          <h2 class="text-xl font-semibold text-white">Security</h2>
          <form method="POST" action="/settings/password" class="mt-6 grid gap-4">
            <div>
              <label class="block text-sm text-slate-300">New password</label>
              <input name="password" type="password" required class="mt-2 w-full rounded-xl border border-white/10 bg-slate-900/70 px-4 py-3 text-sm text-white placeholder:text-slate-500" placeholder="Create a strong password" />
            </div>
            <div>
              <button class="w-full rounded-full border border-white/20 px-5 py-3 text-sm font-semibold text-white/80 transition hover:border-white hover:text-white">Update password</button>
            </div>
          </form>
        </section>

        <section class="rounded-3xl border border-white/10 bg-slate-950/70 p-8">
          <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <h2 class="text-xl font-semibold text-white">GitHub integration</h2>
              <p class="mt-2 text-sm text-slate-300">
                ${githubConnected ? "GitHub is connected to your account." : "Connect GitHub to sync your latest work."}
              </p>
            </div>
            ${
              githubConnected
                ? `<form method="POST" action="/settings/github/disconnect">
                    <button class="rounded-full border border-rose-400/60 px-5 py-2 text-sm font-semibold text-rose-200 transition hover:border-rose-300 hover:text-rose-100">Disconnect</button>
                  </form>`
                : `<form method="POST" action="/auth/github/connect">
                    <button class="rounded-full bg-white px-5 py-2 text-sm font-semibold text-slate-900 transition hover:-translate-y-0.5 hover:shadow-lg">Connect GitHub</button>
                  </form>`
            }
          </div>
        </section>

        <section class="rounded-3xl border border-rose-500/40 bg-rose-500/5 p-8">
          <h2 class="text-xl font-semibold text-white">Delete account</h2>
          <p class="mt-2 text-sm text-slate-300">
            This will permanently delete your account and all associated data.
          </p>
          <form method="POST" action="/settings/delete" class="mt-6">
            <button class="rounded-full border border-rose-400/60 px-5 py-2 text-sm font-semibold text-rose-200 transition hover:border-rose-300 hover:text-rose-100">Delete account</button>
          </form>
        </section>
      </div>
    </main>
  `;

  res.send(layout({ title: "Settings | Solus Labs", body }));
});

app.get("/repo/select", (req, res) => {
  if (!requireAuth(req, res)) return;

  const fullName = String(req.query.full_name || "");
  if (!fullName || !fullName.includes("/")) {
    res.redirect("/home");
    return;
  }

  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) {
    res.redirect("/home");
    return;
  }

  res.redirect(`/repo/${owner}/${repo}`);
});

app.get("/repo/:owner/:repo", async (req, res) => {
  if (!requireAuth(req, res)) return;

  const owner = req.params.owner;
  const repo = req.params.repo;

  if (!owner || !repo) {
    res.redirect("/home");
    return;
  }

  if (!req.session.githubToken) {
    const stored = await loadGithubTokens(req.session.user?.id);
    if (stored?.provider_token) {
      req.session.githubToken = stored.provider_token;
    }
  }

  if (!req.session.githubToken) {
    res.redirect("/home?message=Reconnect%20GitHub%20to%20view%20repo%20details");
    return;
  }

  try {
    let token = req.session.githubToken;
    try {
      const repoData = await fetchRepoDetails(token, owner, repo);
      const errorsForge = await fetchErrorsForge(token, owner, repo);

      const entriesMarkup =
        errorsForge.status === "ok"
          ? errorsForge.entries
              .map(
                (entry, index) => `
                  <div class="rounded-2xl border border-white/10 bg-slate-950/70 p-6">
                    <p class="text-xs uppercase tracking-[0.2em] text-emerald-200">Entry ${index + 1}</p>
                    <h3 class="mt-3 text-sm font-semibold text-white">Problem</h3>
                    <p class="mt-2 text-sm text-slate-300">${entry.problem || "No problem text provided."}</p>
                    <h3 class="mt-5 text-sm font-semibold text-white">Solution</h3>
                    <p class="mt-2 text-sm text-slate-300">${entry.solution || "No solution text provided."}</p>
                  </div>
                `
              )
              .join("")
          : "";

      const statusMessage =
        errorsForge.status === "missing"
          ? "No errors.forge file was found. Run the Forge-RDE VSCode Extension to generate one."
          : errorsForge.status === "empty"
            ? "errors.forge exists but has no contents yet. It will be filled in as your AI Agent helps you throughout your project."
            : errorsForge.status === "invalid"
              ? "errors.forge exists but could not be parsed as JSON."
              : "";

      const body = `
        ${navbar({ sessionData: req.session, showAuth: false, showLinks: false })}
        <main class="mx-auto w-full max-w-5xl px-6 py-16">
          <div class="flex flex-col gap-8 rounded-3xl border border-white/10 bg-white/5 p-10">
            <div>
              <p class="text-sm uppercase tracking-[0.2em] text-emerald-300">Repository</p>
              <h1 class="mt-3 text-3xl font-semibold text-white">${repoData.full_name}</h1>
              <p class="mt-3 text-slate-300">${repoData.description || "No description provided."}</p>
              <div class="mt-6 flex flex-wrap items-center gap-4 text-xs text-slate-400">
                <span class="rounded-full border border-white/10 px-3 py-1">${repoData.private ? "Private" : "Public"}</span>
                <span>${repoData.language || "Unknown language"}</span>
                <span>★ ${repoData.stargazers_count || 0}</span>
                <span>⑂ ${repoData.forks_count || 0}</span>
                <span>Updated ${new Date(repoData.updated_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}</span>
              </div>
            </div>

            <section class="rounded-3xl border border-white/10 bg-slate-950/70 p-8">
              <div class="flex items-center justify-between">
                <h2 class="text-xl font-semibold text-white">errors.forge</h2>
                <span class="text-xs uppercase tracking-[0.2em] text-slate-400">.rde/errors.forge</span>
              </div>
              ${
                statusMessage
                  ? `<div class="mt-4 rounded-2xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">${statusMessage}</div>`
                  : ""
              }
              ${
                errorsForge.status === "ok"
                  ? `<div class="mt-6 grid gap-4">${entriesMarkup}</div>`
                  : ""
              }
            </section>
          </div>
        </main>
      `;

      res.send(layout({ title: `${repoData.full_name} | Solus Labs`, body }));
      return;
    } catch (err) {
      if (err?.status !== 401) {
        throw err;
      }
    }

    const refreshed = await refreshTokenIfNeeded(req.session);
    if (!refreshed) {
      res.redirect("/home?message=GitHub%20token%20expired.%20Reconnect%20GitHub%20to%20continue");
      return;
    }

    token = refreshed;
    const repoData = await fetchRepoDetails(token, owner, repo);
    const errorsForge = await fetchErrorsForge(token, owner, repo);

    const entriesMarkup =
      errorsForge.status === "ok"
        ? errorsForge.entries
            .map(
              (entry, index) => `
                <div class="rounded-2xl border border-white/10 bg-slate-950/70 p-6">
                  <p class="text-xs uppercase tracking-[0.2em] text-emerald-200">Entry ${index + 1}</p>
                  <h3 class="mt-3 text-sm font-semibold text-white">Problem</h3>
                  <p class="mt-2 text-sm text-slate-300">${entry.problem || "No problem text provided."}</p>
                  <h3 class="mt-5 text-sm font-semibold text-white">Solution</h3>
                  <p class="mt-2 text-sm text-slate-300">${entry.solution || "No solution text provided."}</p>
                </div>
              `
            )
            .join("")
        : "";

    const statusMessage =
      errorsForge.status === "missing"
        ? "No errors.forge file was found. Run the Forge-RDE VSCode Extension to generate one."
        : errorsForge.status === "empty"
          ? "errors.forge exists but has no contents yet. It will be filled in as your AI Agent helps you throughout your project."
          : errorsForge.status === "invalid"
            ? "errors.forge exists but could not be parsed as JSON."
            : "";

    const body = `
      ${navbar({ sessionData: req.session, showAuth: false, showLinks: false })}
      <main class="mx-auto w-full max-w-5xl px-6 py-16">
        <div class="flex flex-col gap-8 rounded-3xl border border-white/10 bg-white/5 p-10">
          <div>
            <p class="text-sm uppercase tracking-[0.2em] text-emerald-300">Repository</p>
            <h1 class="mt-3 text-3xl font-semibold text-white">${repoData.full_name}</h1>
            <p class="mt-3 text-slate-300">${repoData.description || "No description provided."}</p>
            <div class="mt-6 flex flex-wrap items-center gap-4 text-xs text-slate-400">
              <span class="rounded-full border border-white/10 px-3 py-1">${repoData.private ? "Private" : "Public"}</span>
              <span>${repoData.language || "Unknown language"}</span>
              <span>★ ${repoData.stargazers_count || 0}</span>
              <span>⑂ ${repoData.forks_count || 0}</span>
              <span>Updated ${new Date(repoData.updated_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}</span>
            </div>
          </div>

          <section class="rounded-3xl border border-white/10 bg-slate-950/70 p-8">
            <div class="flex items-center justify-between">
              <h2 class="text-xl font-semibold text-white">errors.forge</h2>
              <span class="text-xs uppercase tracking-[0.2em] text-slate-400">.rde/errors.forge</span>
            </div>
            ${
              statusMessage
                ? `<div class="mt-4 rounded-2xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">${statusMessage}</div>`
                : ""
            }
            ${
              errorsForge.status === "ok"
                ? `<div class="mt-6 grid gap-4">${entriesMarkup}</div>`
                : ""
            }
          </section>
        </div>
      </main>
    `;

    res.send(layout({ title: `${repoData.full_name} | Solus Labs`, body }));
  } catch (err) {
    res.redirect("/home?message=Unable%20to%20load%20repository");
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      res.redirect(`/login?message=${encodeURIComponent(error.message)}`);
      return;
    }

    req.session.user = data.user;
    req.session.profile = {
      first_name: data.user?.user_metadata?.first_name || ""
    };
    req.session.access_token = data.session?.access_token || "";
    req.session.refresh_token = data.session?.refresh_token || "";
    req.session.githubConnected = await resolveGithubIdentity(req.session);
    if (req.session.githubConnected) {
      const stored = await loadGithubTokens(data.user?.id);
      if (stored?.provider_token) {
        req.session.githubToken = stored.provider_token;
      }
    }
    res.redirect("/home");
  } catch (err) {
    res.redirect(`/login?message=${encodeURIComponent("Login failed")}`);
  }
});

app.post("/auth/signup", async (req, res) => {
  const { email, password, first_name } = req.body;

  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          first_name
        }
      }
    });

    if (error) {
      res.redirect(`/signup?message=${encodeURIComponent(error.message)}`);
      return;
    }

    if (data.session) {
      req.session.user = data.user;
      req.session.profile = { first_name };
      req.session.access_token = data.session.access_token;
      req.session.refresh_token = data.session.refresh_token || "";
      res.redirect("/home");
      return;
    }

    res.redirect(
      "/signup?message=" +
        encodeURIComponent("Check your email to confirm your account before logging in.")
    );
  } catch (err) {
    res.redirect(`/signup?message=${encodeURIComponent("Signup failed")}`);
  }
});

app.post("/auth/github/connect", async (req, res) => {
  if (!requireAuth(req, res)) return;

  try {
    if (!req.session.refresh_token) {
      req.session.githubError =
        "Please log out and log back in before connecting GitHub.";
      res.redirect("/home");
      return;
    }

    const userClient = await createUserClient(req.session);
    const { data, error } = await userClient.auth.linkIdentity({
      provider: "github",
      options: {
        redirectTo: `${APP_URL}/auth/github/callback`,
        scopes: "read:user repo"
      }
    });

    if (error || !data?.url) {
      if (String(error?.message || "").includes("identity already exists")) {
        const fallback = await userClient.auth.signInWithOAuth({
          provider: "github",
          options: {
            redirectTo: `${APP_URL}/auth/github/callback`,
            scopes: "read:user repo"
          }
        });
        if (fallback?.data?.url) {
          res.redirect(fallback.data.url);
          return;
        }
      }
      req.session.githubError = error?.message || "Unable to start GitHub connection.";
      res.redirect("/home");
      return;
    }

    res.redirect(data.url);
  } catch (err) {
    req.session.githubError = "Unable to start GitHub connection.";
    console.error("GitHub connect failed", err);
    res.redirect("/home");
  }
});

app.post("/settings/profile", async (req, res) => {
  if (!requireAuth(req, res)) return;

  const first_name = String(req.body.first_name || "").trim();

  if (!first_name) {
    res.redirect("/settings?message=First%20name%20is%20required");
    return;
  }

  try {
    const userClient = await createUserClient(req.session);
    const { data, error } = await userClient.auth.updateUser({
      data: { first_name }
    });

    if (error) {
      res.redirect(`/settings?message=${encodeURIComponent(error.message)}`);
      return;
    }

    req.session.user = data.user;
    req.session.profile = { first_name };
    res.redirect("/settings?message=Profile%20updated");
  } catch (err) {
    res.redirect("/settings?message=Unable%20to%20update%20profile");
  }
});

app.post("/settings/password", async (req, res) => {
  if (!requireAuth(req, res)) return;

  const password = String(req.body.password || "");
  if (password.length < 8) {
    res.redirect("/settings?message=Password%20must%20be%20at%20least%208%20characters");
    return;
  }

  try {
    const userClient = await createUserClient(req.session);
    const { error } = await userClient.auth.updateUser({ password });

    if (error) {
      res.redirect(`/settings?message=${encodeURIComponent(error.message)}`);
      return;
    }

    res.redirect("/settings?message=Password%20updated");
  } catch (err) {
    res.redirect("/settings?message=Unable%20to%20update%20password");
  }
});

app.post("/settings/github/disconnect", async (req, res) => {
  if (!requireAuth(req, res)) return;

  try {
    const userClient = await createUserClient(req.session);
    const { error } = await userClient.auth.unlinkIdentity({
      provider: "github"
    });

    if (error) {
      res.redirect(`/settings?message=${encodeURIComponent(error.message)}`);
      return;
    }

    req.session.githubConnected = false;
    req.session.githubToken = "";
    req.session.githubRepos = [];
    await clearGithubTokens(req.session.user?.id);
    res.redirect("/settings?message=GitHub%20disconnected");
  } catch (err) {
    res.redirect("/settings?message=Unable%20to%20disconnect%20GitHub");
  }
});

app.post("/settings/delete", async (req, res) => {
  if (!requireAuth(req, res)) return;

  if (!supabaseAdmin) {
    res.redirect(
      "/settings?message=Add%20SUPABASE_SERVICE_ROLE_KEY%20to%20enable%20account%20deletion"
    );
    return;
  }

  try {
    const userId = req.session.user?.id;
    if (!userId) {
      res.redirect("/settings?message=Unable%20to%20find%20user");
      return;
    }

    const { error } = await supabaseAdmin.auth.admin.deleteUser(userId);
    if (error) {
      res.redirect(`/settings?message=${encodeURIComponent(error.message)}`);
      return;
    }

    req.session.destroy(() => {
      res.redirect("/");
    });
  } catch (err) {
    res.redirect("/settings?message=Unable%20to%20delete%20account");
  }
});

app.get("/auth/github/callback", async (req, res) => {
  const { code, error } = req.query;

  if (error) {
    res.redirect("/home");
    return;
  }

  if (code && typeof code === "string") {
    try {
      const { data, error: exchangeError } = await supabase.auth.exchangeCodeForSession(code);

      if (exchangeError) {
        res.redirect("/home");
        return;
      }

      req.session.user = data.user;
      req.session.profile = {
        first_name: data.user?.user_metadata?.first_name || ""
      };
      req.session.access_token = data.session?.access_token || "";
      req.session.refresh_token = data.session?.refresh_token || "";

      if (data.session?.provider_token) {
        req.session.githubToken = data.session.provider_token;
        req.session.githubConnected = true;
        req.session.githubError = "";

        await storeGithubTokens(
          req.session.user?.id,
          data.session.provider_token,
          data.session.provider_refresh_token
        );

        try {
          req.session.githubRepos = await fetchGithubRepos(data.session.provider_token);
        } catch (repoError) {
          req.session.githubRepos = [];
          req.session.githubError = "We connected to GitHub, but couldn't load repos yet.";
        }
      } else {
        const identities = data.user?.identities || [];
        req.session.githubConnected = identities.some((identity) => identity.provider === "github");
        req.session.githubError =
          "GitHub connected, but no provider token was returned. Enable provider tokens in Supabase Auth settings to load repos.";
      }

      res.redirect("/home");
      return;
    } catch (err) {
      res.redirect("/home");
      return;
    }
  }

  res.send(
    layout({
      title: "GitHub 연결 중...",
      body: `
        <main class="mx-auto flex min-h-screen w-full max-w-xl items-center justify-center px-6">
          <div class="rounded-2xl border border-white/10 bg-white/5 p-6 text-center">
            <p class="text-sm text-slate-300">Connecting to GitHub…</p>
          </div>
        </main>
        <script>
          const hash = window.location.hash?.replace(/^#/, "");
          if (!hash) {
            window.location.href = "/home";
          } else {
            const params = new URLSearchParams(hash);
            fetch("/auth/github/callback/complete", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              access_token: params.get("access_token"),
              refresh_token: params.get("refresh_token"),
              provider_token: params.get("provider_token"),
              provider_refresh_token: params.get("provider_refresh_token")
            })
          })
              .then(() => {
                window.location.replace("/home");
              })
              .catch(() => {
                window.location.replace("/home");
              });
          }
        </script>
      `
    })
  );
});

app.post("/auth/github/callback/complete", async (req, res) => {
  const { access_token, refresh_token, provider_token, provider_refresh_token } =
    req.body || {};

  if (!access_token) {
    res.status(400).json({ ok: false });
    return;
  }

  try {
    const userClient = createClient(SUPABASE_URL || "", apiKey, {
      auth: { persistSession: false, detectSessionInUrl: false }
    });

    const { data, error } = await userClient.auth.getUser(access_token);

    if (error) {
      res.status(400).json({ ok: false });
      return;
    }

    req.session.user = data.user;
    req.session.profile = {
      first_name: data.user?.user_metadata?.first_name || ""
    };
    req.session.access_token = access_token;
    req.session.refresh_token = refresh_token || "";
    req.session.githubToken = provider_token || "";
    req.session.githubConnected = Boolean(provider_token);
    req.session.githubError = provider_token
      ? ""
      : "GitHub connected, but no provider token was returned. Enable provider tokens in Supabase Auth settings to load repos.";

    if (provider_token) {
      await storeGithubTokens(
        req.session.user?.id,
        provider_token,
        provider_refresh_token
      );
      try {
        req.session.githubRepos = await fetchGithubRepos(provider_token);
      } catch (repoError) {
        req.session.githubRepos = [];
        req.session.githubError = "We connected to GitHub, but couldn't load repos yet.";
      }
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false });
  }
});

app.post("/auth/github/callback/error", (req, res) => {
  const { error_description } = req.body || {};
  req.session.githubError =
    error_description || "GitHub connection failed. Please try again.";
  res.json({ ok: true });
});

app.post("/auth/logout", async (req, res) => {
  try {
    if (req.session?.access_token) {
      await supabase.auth.signOut();
    }
  } catch (err) {
    // ignore signout errors
  }

  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(Number(PORT), () => {
  console.log(`Solus Labs server listening on http://localhost:${PORT}`);
});
