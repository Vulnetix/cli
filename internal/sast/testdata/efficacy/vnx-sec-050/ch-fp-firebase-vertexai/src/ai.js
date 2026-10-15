import { initializeApp } from "firebase/app";
import { getVertexAI, getGenerativeModel } from "firebase/vertexai";

const app = initializeApp({
  apiKey: "AIza@@sample:[A-Za-z0-9_-]{35}@@",
  authDomain: "acme-chat.firebaseapp.com",
  projectId: "acme-chat",
  appId: "1:123456789012:web:abcdef123456",
});

export const model = getGenerativeModel(getVertexAI(app), { model: "gemini-1.5-flash" });
