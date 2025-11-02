// renderer/components/Settings.jsx
import React, { useState } from 'react';

export default function Settings({ onLock }) {
  const [oldPass, setOldPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [newPass2, setNewPass2] = useState('');
  const [msg, setMsg] = useState('');

  async function change() {
    setMsg('');
    if (newPass.length < 4) return setMsg('Новый пароль минимум 4 символа');
    if (newPass !== newPass2) return setMsg('Пароли не совпадают');
    const r = await window.api.changePassword(oldPass, newPass);
    if (r.ok) { setMsg('Пароль успешно изменён'); setOldPass(''); setNewPass(''); setNewPass2(''); }
    else setMsg(r.error || 'Ошибка');
  }

  return (
    <div>
      <h2>Настройки</h2>
      <div style={{ maxWidth: 520 }}>
        <h4>Сменить мастер-пароль</h4>
        <input type="password" placeholder="Старый пароль" value={oldPass} onChange={e=>setOldPass(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
        <input type="password" placeholder="Новый пароль" value={newPass} onChange={e=>setNewPass(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
        <input type="password" placeholder="Повторите новый пароль" value={newPass2} onChange={e=>setNewPass2(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
        <div style={{ color: 'green', minHeight: 18 }}>{msg}</div>
        <div style={{ marginTop: 10 }}>
          <button onClick={change}>Изменить пароль</button>
          <button onClick={onLock} style={{ marginLeft: 10 }}>Заблокировать</button>
        </div>
      </div>
    </div>
  );
}
