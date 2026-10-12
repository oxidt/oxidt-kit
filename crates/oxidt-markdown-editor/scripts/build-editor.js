// Keep third-party notices in the shipped bundle, including dependencies Bun
// tree-shakes partially. The checked-in output keeps cargo builds self-contained.
const result = await Bun.build({
    entrypoints: ["scripts/markdown-editor.js"],
    target: "browser",
    minify: true,
});
if (!result.success) throw new AggregateError(result.logs, "Editor bundle failed");

const packages = new Set();
const notices = new Map();
async function license(name) {
    if (packages.has(name)) return;
    packages.add(name);
    const dir = "node_modules/" + name;
    const pkg = await Bun.file(dir + "/package.json").json();
    const text = (await Bun.file(dir + "/LICENSE").text()).trim();
    notices.set(text, [...(notices.get(text) || []), name]);
    for (const dependency of Object.keys(pkg.dependencies || {}).sort()) await license(dependency);
}
const pkg = await Bun.file("package.json").json();
for (const name of Object.keys(pkg.dependencies).sort()) await license(name);
const header = [...notices].map(([text, names]) => names.join(", ") + "\n\n" + text).join("\n\n---\n\n");
await Bun.write("assets/markdown-editor.js", "/*!\n" + header + "\n*/\n" + await result.outputs[0].text());
