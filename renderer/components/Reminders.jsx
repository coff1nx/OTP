// renderer/components/Reminders.jsx
import React, { useEffect, useState } from "react";

export default function Reminders(){
  const [items, setItems] = useState([]);
  const [text, setText] = useState('');
  const [due, setDue] = useState('');

  useEffect(()=>{ load(); const onF=(e)=> alertBig(e.detail.text); window.addEventListener('reminder:fired', onF); return ()=> window.removeEventListener('reminder:fired', onF); }, []);

  async function load(){ const l = await window.api.remindersList(); setItems(l||[]); }
  async function create(){
    const ts = due ? (new Date(due)).getTime() : null;
    const r = await window.api.remindersCreate({ text, due: ts });
    if (r.ok) { setText(''); setDue(''); load(); } else alert('Ошибка: '+(r.error||''));
  }
  async function del(id){ if(!confirm('Удалить?')) return; const r = await window.api.remindersDelete(id); if (r.ok) load(); else alert('Ошибка'); }

  function alertBig(txt){ // show big modal-like alert
    const w = window.open('', '', 'width=600,height=400');
    w.document.write(`<body style="display:flex;align-items:center;justify-content:center;font-family:Segoe UI"><div style="padding:20px"><h1>${txt}</h1></div></body>`);
  }

  return (
    <div style={{ display:'flex', height:'100%' }}>
      <div style={{ width:360, borderRight:'1px solid #eee', padding:12 }}>
        <h3>Напоминания</h3>
        <div style={{ marginBottom:8 }}>
          <textarea placeholder="Текст напоминания" value={text} onChange={e=>setText(e.target.value)} style={{ width:'100%', height:80 }} />
          <input type="datetime-local" value={due} onChange={e=>setDue(e.target.value)} style={{ width:'100%', marginTop:8 }} />
          <div style={{ marginTop:8 }}>
            <button onClick={create}>Создать</button>
          </div>
        </div>

        <div>
          {items.map(it => (
            <div key={it.id} style={{ padding:10, background:'#fafafa', marginBottom:8, borderRadius:6 }}>
              <div style={{ fontWeight:600 }}>{it.text ? it.text.slice(0,40) : '—'}</div>
              <div style={{ fontSize:12, color:'#666' }}>{it.due ? new Date(it.due).toLocaleString() : 'Нет даты'}</div>
              <div style={{ marginTop:8 }}>
                <button onClick={()=>del(it.id)} style={{ color:'red' }}>Удалить</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex:1, padding:16 }}>
        <h3>Инструкции</h3>
        <p>Установи дату/время, когда нужно показать напоминание — при наступлении времени откроется большое окно с текстом.</p>
      </div>
    </div>
  );
}
