import React from "react";
import ReactDOM from "react-dom/client";
import Wallet from "./Wallet";
import Benchmark from "./Benchmark";
import "./styles.css";

function Root() {
  // Minimal routing without a router dependency: /benchmark is the debug page.
  return window.location.pathname === "/benchmark" ? <Benchmark /> : <Wallet />;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
