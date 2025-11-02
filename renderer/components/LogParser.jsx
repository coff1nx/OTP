// renderer/components/LogParser.jsx
import React, { useState } from "react";

export default function LogParser(){
  const [k1, setK1] = useState('');
  const [k2, setK2] = useState('');
  const [log, setLog] = useState('');
  const [result, setResult] = useState(null);

  function check(){
    const lower = log.toLowerCase();
    const found1 = k1 ? lower.includes(k1.toLowerCase()) : false;
    const found2 = k2 ? lower.includes(k2.toLowerCase()) : false;
    setResult({found1, found2});
    // show modal with highlighting
    const w = window.open('', '', 'width=900,height=600');
    const html = log
      .replace(new RegExp(k1, 'gi'), (m)=>`<mark style="background: #c8f7c5">${m}</mark>`)
      .replace(new RegExp(k2, 'gi'), (m)=>`<mark style="background: #c8f7c5">${m}</mark>`);
    w.document.write(`<body style="font-family:Segoe UI;padding:12px"><h3>Результат</h3><div>${html.replace(/\n/g,'<br/>')}</div></body>`);
  }

  return (
    <div>
      <h3>Парсер лога</h3>
      <div style={{ display:'flex', gap:8 }}>
        <input placeholder="Ключ 1" value={k1} onChange={e=>setK1(e.target.value)} />
        <input placeholder="Ключ 2" value={k2} onChange={e=>setK2(e.target.value)} />
      </div>
      <div style={{ marginTop:10 }}>
        <textarea rows={18} value={log} onChange={e=>setLog(e.target.value)} style={{ width:'100%' }} placeholder="Вставь лог сюда" />
      </div>
      <div style={{ marginTop:8 }}>
        <button onClick={check}>Проверить</button>
      </div>
      {result && (
        <div style={{ marginTop:8 }}>
          <div>{result.found1 ? 'Найдено: ' + k1 : 'Не найдено: ' + k1}</div>
          <div>{result.found2 ? 'Найдено: ' + k2 : 'Не найдено: ' + k2}</div>
        </div>
      )}
    </div>
  );
}
