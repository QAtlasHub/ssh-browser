// An ES module with a relative import and a relative fetch.
//
// Both are the point of the whole project: `file://` is an opaque origin, so the import
// fails with a CORS error and the fetch is refused outright. Over a real http origin they
// simply work, and this file is what makes that difference observable in a DOM.
import { label } from "./dep.mjs";

document.getElementById("module").textContent = label;

// Resolved against this module rather than against the document. `fetch` takes the
// document's base URL for a bare relative string, so `"./data.json"` from a module under
// `/assets/` asks for `/data.json` — a real 404, and the first thing this harness caught.
// `import.meta.url` is module-only too, so this exercises a third thing `file://` breaks.
const res = await fetch(new URL("./data.json", import.meta.url));
const data = await res.json();
document.getElementById("fetched").textContent = data.answer;
