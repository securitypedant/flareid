#!/usr/bin/env node
// Generates a large, realistic test directory as CSV, for load-testing the
// importer and everything downstream of it (group resolution, claims, SCIM,
// the admin lists).
//
//   node scripts/generate-test-directory.mjs [--users 10000] [--out test-data] [--seed 42]
//
// Writes <out>/users.csv and <out>/groups.csv in the format the admin CSV
// import accepts (Admin -> Users -> Import CSV; see docs/csv-import.md):
//
//   groups.csv  name,description,rule
//               rule is empty for a static group, or rule JSON for a dynamic one
//   users.csv   username,given_name,family_name,display_name,email,job_title,
//               department,employee_number,hire_date,employment_status,
//               employment_type,location,manager,status,groups
//               groups is semicolon-separated static group names; manager is
//               another row's username
//
// Deterministic for a given seed, so two runs produce the same directory and
// a re-import converges instead of duplicating. The output directory is
// gitignored: 10,000 fictional people do not belong in the repository.
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const USERS = Number(arg("users", "10000"));
const OUT = resolve(arg("out", "test-data"));
let seed = Number(arg("seed", "42"));

// mulberry32: small, fast, and reproducible - Math.random() is neither seedable nor stable across runs.
function rand() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = (list) => list[Math.floor(rand() * list.length)];

const FIRST = ["Ada", "Alan", "Amara", "Ana", "Arjun", "Ava", "Ben", "Bianca", "Carlos", "Chen", "Chloe", "Daniel", "Dara", "Elena", "Eli", "Emma", "Farah", "Felix", "Grace", "Hana", "Hugo", "Ines", "Isaac", "Ivy", "Jamal", "Jin", "Julia", "Kai", "Kenji", "Lara", "Leo", "Lina", "Luca", "Maya", "Mateo", "Mei", "Nadia", "Noah", "Nora", "Omar", "Priya", "Quinn", "Rafael", "Rosa", "Sam", "Sana", "Sofia", "Tariq", "Theo", "Uma", "Vera", "Wei", "Yara", "Yusuf", "Zara", "Zoe"];
const LAST = ["Abara", "Andersen", "Bauer", "Chen", "Costa", "Dubois", "Eriksen", "Fischer", "Garcia", "Gupta", "Haddad", "Hughes", "Ito", "Jansen", "Kaur", "Kim", "Kowalski", "Larsen", "Lopez", "Martin", "Mensah", "Moreau", "Murphy", "Nakamura", "Nguyen", "Novak", "Okafor", "Olsen", "Patel", "Petrov", "Quinn", "Rossi", "Santos", "Schmidt", "Silva", "Singh", "Sato", "Tanaka", "Torres", "Varga", "Wagner", "Walsh", "Weber", "Wong", "Yilmaz", "Zhang"];
const DEPARTMENTS = ["Engineering", "Sales", "Marketing", "Finance", "HR", "Legal", "Support", "Operations", "Product", "Security", "IT", "Research"];
const TITLES = {
  Engineering: ["Software Engineer", "Senior Software Engineer", "Staff Engineer", "SRE"],
  Sales: ["Account Executive", "Sales Engineer", "Sales Development Rep"],
  Marketing: ["Marketing Manager", "Content Strategist", "Designer"],
  Finance: ["Accountant", "Financial Analyst", "Controller"],
  HR: ["HR Business Partner", "Recruiter", "People Ops Specialist"],
  Legal: ["Counsel", "Paralegal", "Compliance Analyst"],
  Support: ["Support Engineer", "Customer Success Manager"],
  Operations: ["Operations Analyst", "Program Manager"],
  Product: ["Product Manager", "UX Researcher"],
  Security: ["Security Engineer", "Security Analyst"],
  IT: ["IT Administrator", "Systems Engineer", "Helpdesk Technician"],
  Research: ["Research Scientist", "Data Scientist"],
};
const LOCATIONS = ["London", "Austin", "Lisbon", "Singapore", "San Francisco", "New York", "Berlin", "Paris", "Sydney", "Toronto", "Tokyo", "Bangalore", "Dublin", "Warsaw", "Mexico City", "Sao Paulo", "Nairobi", "Dubai", "Stockholm", "Remote"];
const TYPES = [["full_time", 0.82], ["part_time", 0.06], ["contractor", 0.1], ["intern", 0.02]];

function weighted(pairs) {
  let r = rand();
  for (const [value, w] of pairs) if ((r -= w) <= 0) return value;
  return pairs[pairs.length - 1][0];
}
const slug = (s) => s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "");
const csv = (v) => {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

// --- Groups -----------------------------------------------------------------
const groups = [];
const teamsByDept = {};
for (const dept of DEPARTMENTS) {
  groups.push({ name: dept, description: `Everyone in ${dept}`, rule: "" });
  teamsByDept[dept] = [];
  const teamCount = Math.max(3, Math.round(12 * (dept === "Engineering" ? 2.5 : dept === "Sales" ? 1.6 : 1)));
  for (let i = 1; i <= teamCount; i++) {
    const name = `${dept} Team ${String(i).padStart(2, "0")}`;
    teamsByDept[dept].push(name);
    groups.push({ name, description: `${dept} squad ${i}`, rule: "" });
  }
}
for (const loc of LOCATIONS) groups.push({ name: `Site - ${loc}`, description: `People based in ${loc}`, rule: "" });
groups.push({ name: "Managers", description: "Everyone with direct reports", rule: "" });
groups.push({ name: "VPN Users", description: "Allowed remote network access", rule: "" });
// Dynamic groups: membership is the rule, never a listed member.
const rule = (field, value, op = "eq") => JSON.stringify({ all: [{ schema: "FlareID HR", field, op, value }] });
groups.push({ name: "All Employees", description: "Full-time employees (dynamic)", rule: rule("employment_type", "full_time") });
groups.push({ name: "Contractors", description: "Contractors (dynamic)", rule: rule("employment_type", "contractor") });
groups.push({ name: "Interns", description: "Interns (dynamic)", rule: rule("employment_type", "intern") });
for (const dept of ["Engineering", "Finance", "Security", "IT"]) {
  groups.push({ name: `${dept} (dynamic)`, description: `Department = ${dept}`, rule: rule("department", dept) });
}
groups.push({ name: "Everyone outside London", description: "location != London (dynamic)", rule: rule("location", "London", "ne") });

// --- Users ------------------------------------------------------------------
const users = [];
const taken = new Set(["admin"]);
function username(first, last) {
  const base = `${slug(first)}.${slug(last)}`;
  if (!taken.has(base)) return taken.add(base), base;
  for (let n = 2; ; n++) if (!taken.has(`${base}${n}`)) return taken.add(`${base}${n}`), `${base}${n}`;
}
function person(dept, title, manager, extraGroups = []) {
  const given = pick(FIRST);
  const family = pick(LAST);
  const type = title === "Chief Executive Officer" ? "full_time" : weighted(TYPES);
  const location = pick(LOCATIONS);
  const year = 2012 + Math.floor(rand() * 14);
  const u = {
    username: username(given, family),
    given_name: given,
    family_name: family,
    display_name: `${given} ${family}`,
    email: "",
    job_title: title,
    department: dept,
    employee_number: `E${String(users.length + 1).padStart(6, "0")}`,
    hire_date: `${year}-${String(1 + Math.floor(rand() * 12)).padStart(2, "0")}-${String(1 + Math.floor(rand() * 28)).padStart(2, "0")}`,
    employment_status: rand() < 0.97 ? "active" : "leave",
    employment_type: type,
    location,
    manager: manager ?? "",
    status: rand() < 0.96 ? "active" : "disabled",
    groups: [dept, `Site - ${location}`, ...extraGroups],
  };
  if (rand() < 0.15) u.groups.push("VPN Users");
  users.push(u);
  return u;
}

// A real reporting line: CEO -> department VPs -> team managers -> people.
const ceo = person("Executive", "Chief Executive Officer", null, ["Managers"]);
ceo.groups = ceo.groups.filter((g) => g !== "Executive");
const managersByTeam = {};
for (const dept of DEPARTMENTS) {
  const vp = person(dept, `VP ${dept}`, ceo.username, ["Managers"]);
  for (const team of teamsByDept[dept]) managersByTeam[team] = person(dept, `${dept} Manager`, vp.username, ["Managers", team]);
}
const teams = Object.keys(managersByTeam);
while (users.length < USERS) {
  const team = pick(teams);
  const dept = team.replace(/ Team \d+$/, "");
  person(dept, pick(TITLES[dept]), managersByTeam[team].username, [team]);
}

mkdirSync(OUT, { recursive: true });
writeFileSync(
  resolve(OUT, "groups.csv"),
  ["name,description,rule", ...groups.map((g) => [g.name, g.description, g.rule].map(csv).join(","))].join("\n") + "\n"
);
const COLS = ["username", "given_name", "family_name", "display_name", "email", "job_title", "department", "employee_number", "hire_date", "employment_status", "employment_type", "location", "manager", "status", "groups"];
writeFileSync(
  resolve(OUT, "users.csv"),
  [COLS.join(","), ...users.map((u) => COLS.map((k) => csv(k === "groups" ? u.groups.join(";") : u[k])).join(","))].join("\n") + "\n"
);

const dynamic = groups.filter((g) => g.rule).length;
console.log(`Wrote ${users.length} users and ${groups.length} groups (${groups.length - dynamic} static, ${dynamic} dynamic) to ${OUT}`);
