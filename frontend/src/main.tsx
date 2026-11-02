import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import "./styles.css";

/**
 * Entry point.
 *
 * The shell lives in `App.tsx`; this file only mounts it. `index.html` is served from the same
 * origin as the API, so every request is same-origin and the CSRF cookie applies.
 */
const container = document.getElementById("root");
if (!container) {
  throw new Error("Root element missing from index.html");
}

ReactDOM.createRoot(container).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
