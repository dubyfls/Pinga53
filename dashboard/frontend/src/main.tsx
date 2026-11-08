// SPDX-License-Identifier: AGPL-3.0-only
// Pinga53 — React entrypoint
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

const el = document.getElementById("root");
if (el) createRoot(el).render(<React.StrictMode><App /></React.StrictMode>);
