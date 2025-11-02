// renderer/components/Passwords.jsx
import React, { useEffect, useState } from "react";

function genPassword({ length=16, upper=true, lower=true, numbers=true, symbols=true }) {
  const lowerChars = 'abcdefghijklmnopqrstuvwxyz';
  const upperChars = lowerChars.toUpperCase();
  const numChars = '0123456789';
  const symChars = '!@#$%^&*()-_=+[]{};:,.<>?';
  let pool = '';
  if (lower) pool += lowerChars;
  if (upper) pool += upperChars;
  if (numbers) pool += numChars;
  if (symbols) pool += symChars;
  if (!pool) return '';
  let out = '';
  for (let i=0;i<length;i++) out += pool[Math.floor(Math.random()*pool.length)];
  return out;
}

export default function Passwords(){
  const [items, setItems] = useState([]);
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({name:'', login:'', password:''});
  const [genOpts, setGenOpts] = useState({length:16, upper:true, lower:true, numbers:true, symbols:true});

  useEffect(()=> load(), []);

  async function load(){ const list = await window.api.passwordsList(); setItems(list || []); }

  async function add(){
    const r = await window.api.passwordsCreate({ name: form.name, login: form.login, password: form.password });
    if (r.ok) { setShowNew(false); setForm({name:'',login:'',password:''}); load(); }
    else alert('Ошибка: '+(r.error||''));
  }

  async function remove(id){ if(!confirm('Удалить?')) return; const r = await window.api.passwordsDelete(id); if(r.ok) load(); else alert('Ошибка'); }

  return (
    <div style={{ display:'flex', height:'100%' }}>
      <div style={{ width:340, borderRight:'1px solid #eee', padding:12, overflowY:'auto' }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <h3>Пароли</h3>
          <button onClick={()=>setShowNew(s=>!s)}>➕</button>
        </div>
        <div>
          {items.map(it => (
            <div key={it.id} style={{ padding:10, borderRadius:6, marginBottom:8, background:'#fafafa' }}>
              <div style={{ fontWeight:600 }}>{it.name}</div>
              <div style={{ fontSize:12, color:'#666' }}>{it.login}</div>
              <div style={{ marginTop:8 }}>
                <button onClick={()=>{ navigator.clipboard.writeText(it.password||''); alert('Пароль скопирован'); }}>Копировать</button>
                <button onClick={()=>remove(it.id)} style={{ marginLeft:8, color:'red' }}>Удалить</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex:1, padding:16 }}>
        {showNew ? (
          <div style={{ maxWidth:600 }}>
            <h3>Новый пароль</h3>
            <input placeholder="Название" value={form.name} onChange={e=>setForm({...form,name:e.target.value})} style={{ width:'100%', padding:8, marginBottom:8 }} />
            <input placeholder="Логин" value={form.login} onChange={e=>setForm({...form,login:e.target.value})} style={{ width:'100%', padding:8, marginBottom:8 }} />
            <div style={{ display:'flex', gap:8 }}>
              <input placeholder="Пароль" value={form.password} onChange={e=>setForm({...form,password:e.target.value})} style={{ flex:1, padding:8 }} />
              <button onClick={()=>setForm({...form,password:genPassword(genOpts)})}>Генерировать</button>
            </div>

            <div style={{ marginTop:8 }}>
              <label>Длина: <input type="number" value={genOpts.length} onChange={e=>setGenOpts({...genOpts,length:Math.max(4, Number(e.target.value||4))})} style={{ width:80 }} /></label>
              <label style={{ marginLeft:8 }}><input type="checkbox" checked={genOpts.upper} onChange={e=>setGenOpts({...genOpts,upper:e.target.checked})} /> A-Z</label>
              <label style={{ marginLeft:8 }}><input type="checkbox" checked={genOpts.numbers} onChange={e=>setGenOpts({...genOpts,numbers:e.target.checked})} /> 0-9</label>
              <label style={{ marginLeft:8 }}><input type="checkbox" checked={genOpts.symbols} onChange={e=>setGenOpts({...genOpts,symbols:e.target.checked})} /> @#$</label>
            </div>

            <div style={{ marginTop:12 }}>
              <button onClick={add}>Сохранить</button>
              <button onClick={()=>setShowNew(false)} style={{ marginLeft:8 }}>Отмена</button>
            </div>
          </div>
        ) : (
          <div style={{ color:'#777' }}>Выберите существующий пароль или нажмите ➕ чтобы добавить новый.</div>
        )}
      </div>
    </div>
  );
}
