import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

if (process.env.NODE_ENV === "production") {
  console.log = () => {};
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
