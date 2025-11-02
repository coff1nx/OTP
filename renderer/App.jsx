import React, { useState, useEffect } from "react";
import Notes from "./components/Notes";
import Passwords from "./components/Passwords";
import Reminders from "./components/Reminders";
import Parser from "./components/Parser";
import Servers from "./components/Servers";
import Settings from "./components/Settings";

export default function App() {
  const [screen, setScreen] = useState("loading");
  const [password, setPassword] = useState("");
  const [inputPassword, setInputPassword] = useState("");

  useEffect(() => {
    window.api.invoke("auth:getStatus").then((exists) => {
      if (exists) setScreen("lock");
      else setScreen("createPassword");
    });
  }, []);

  const createPassword = async () => {
    if (!password) return;
    await window.api.invoke("auth:setPassword", password);
    setScreen("main");
  };

  const unlock = async () => {
    const ok = await window.api.invoke("auth:checkPassword", inputPassword);
    if (ok) setScreen("main");
    else alert("Неверный пароль");
  };

  if (screen === "loading") return <div>Загрузка...</div>;

  if (screen === "createPassword")
    return (
      <div className="p-8">
        <h2>Создайте пароль</h2>
        <input type="password" value={password} onChange={e=>setPassword(e.target.value)} />
        <button onClick={createPassword}>Сохранить</button>
      </div>
    );

  if (screen === "lock")
    return (
      <div className="p-8">
        <h2>Введите пароль</h2>
        <input type="password" value={inputPassword} onChange={e=>setInputPassword(e.target.value)} />
        <button onClick={unlock}>Разблокировать</button>
      </div>
    );

  return (
    <div className="flex h-screen">
      <aside className="w-48 bg-gray-800 text-white p-3 flex flex-col">
        {["notes", "passwords", "reminders", "parser", "servers", "settings"].map((tab) => (
          <button
            key={tab}
            onClick={() => setScreen(tab)}
            className="p-2 my-1 hover:bg-gray-700"
          >
            {tab}
          </button>
        ))}
        <button onClick={() => setScreen("lock")} className="mt-auto bg-red-600 p-2 rounded">
          🔒 Заблокировать
        </button>
      </aside>

      <main className="flex-1 p-4 overflow-auto">
        {screen === "notes" && <Notes />}
        {screen === "passwords" && <Passwords />}
        {screen === "reminders" && <Reminders />}
        {screen === "parser" && <Parser />}
        {screen === "servers" && <Servers />}
        {screen === "settings" && <Settings />}
      </main>
    </div>
  );
}
