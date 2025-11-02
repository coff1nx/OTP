// renderer/components/Servers.jsx
import React, { useEffect, useState } from "react";

export default function Servers(){
  const [items, setItems] = useState([]);
  const [host, setHost] = useState('');
  const [desc, setDesc] = useState('');

  useEffect(()=> load(), []);

  async function load(){ const l = await window.api.serversList(); setItems(l||[]); }
  async function add(){ const r = await window.api.serversCreate({ host, desc }); if (r.ok) { setHost(''); setDesc(''); load(); } else alert('Ошибка'); }
  async function del(id){ if(!confirm('Удалить?')) return; const r = await window.api.serversDelete(id); if(r.ok) load(); else alert('Ошибка'); }

  return (
    <div style={{ display:'flex', height:'100%' }}>
      <div style={{ width:360, borderRight:'1px solid #eee', padding:12 }}>
        <h3>Серверы</h3>
        <input placeholder="IP / Host" value={host} onChange={e=>setHost(e.target.value)} style={{ width:'100%', padding:8, marginBottom:8 }} />
        <input placeholder="Описание" value={desc} onChange={e=>setDesc(e.target.value)} style={{ width:'100%', padding:8, marginBottom:8 }} />
        <button onClick={add}>Добавить</button>

        <div style={{ marginTop:12 }}>
          {items.map(it => (
            <div key={it.id} style={{ padding:10, background:'#fafafa', marginBottom:8, borderRadius:6 }}>
              <div style={{ fontWeight:600 }}>{it.host}</div>
              <div style={{ fontSize:12, color:'#666' }}>{it.desc}</div>
              <div style={{ marginTop:8 }}>
                <button onClick={()=>{ navigator.clipboard.writeText(it.host); alert('Скопировано'); }}>Копировать</button>
                <button onClick={()=>del(it.id)} style={{ marginLeft:8, color:'red' }}>Удалить</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex:1, padding:16 }}>
        <h3>Инфо</h3>
        <p>Сохраняй IP и описание — быстро копируй адреса для RDP/SSH.</p>
      </div>
    </div>
  );
}
