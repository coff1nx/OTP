// renderer/components/Notes.jsx
import React, { useEffect, useState, useRef } from "react";

export default function Notes() {
  const [notes, setNotes] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const saveTimer = useRef(null);

  useEffect(() => { load(); }, []);

  async function load() {
    const list = await window.api.notesList();
    setNotes(list || []);
    if (list && list.length) {
      setActiveId(list[0].id);
      setTitle(list[0].title || '');
      setBody(list[0].body || '');
    } else {
      setActiveId(null); setTitle(''); setBody('');
    }
  }

  async function addNew() {
    const r = await window.api.notesCreate({ title: 'Новая заметка', body: '' });
    if (r && r.ok) {
      await load();
      // select created
      setTimeout(() => setActiveId(r.id), 200);
    } else {
      alert('Ошибка создания: ' + (r.error || ''));
    }
  }

  async function removeNote(id) {
    if (!confirm('Удалить запись?')) return;
    const r = await window.api.notesDelete(id);
    if (r.ok) await load();
    else alert('Ошибка: ' + (r.error || ''));
  }

  // when activeId changes, load its content into editor
  useEffect(() => {
    const n = notes.find(n => n.id === activeId);
    if (n) { setTitle(n.title || ''); setBody(n.body || ''); }
    else { setTitle(''); setBody(''); }
  }, [activeId, notes]);

  // auto-save on edits (debounced)
  useEffect(() => {
    if (!activeId) return;
    if (saveTimer.current) clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(async () => {
      const r = await window.api.notesUpdate({ id: activeId, title, body });
      if (!r.ok) console.error('Save failed', r.error);
      const list = await window.api.notesList();
      setNotes(list || []);
    }, 800); // autosave after 800ms of inactivity
    return () => { if (saveTimer.current) clearTimeout(saveTimer.current); };
  }, [title, body, activeId]);

  return (
    <div style={{ display: 'flex', height: '100%' }}>
      <div style={{ width: 340, borderRight: '1px solid #eee', padding: 12, overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3>Заметки</h3>
          <div>
            <button onClick={addNew} style={{ marginRight: 8 }}>➕</button>
          </div>
        </div>
        <div>
          {notes.map(n => (
            <div key={n.id} style={{
              padding: 10, borderRadius: 6, marginBottom: 8,
              background: activeId === n.id ? '#eef6ff' : '#fafafa',
              cursor: 'pointer'
            }}
                 onClick={() => setActiveId(n.id)}>
              <div style={{ fontWeight: 600 }}>{n.title || 'Без названия'}</div>
              <div style={{ fontSize: 12, color: '#666', marginTop: 6 }}>{(n.body||'').slice(0,80)}{(n.body||'').length>80 ? '…' : ''}</div>
              <div style={{ marginTop: 8 }}>
                <button onClick={(e)=>{ e.stopPropagation(); navigator.clipboard.writeText(n.body || ''); alert('Скопировано'); }} style={{ marginRight: 6 }}>Копировать</button>
                <button onClick={(e)=>{ e.stopPropagation(); removeNote(n.id); }} style={{ color: 'red' }}>Удалить</button>
              </div>
            </div>
          ))}
          {!notes.length && <div style={{ color: '#777', marginTop: 12 }}>Пока нет заметок — нажми ➕</div>}
        </div>
      </div>

      <div style={{ flex: 1, padding: 16 }}>
        {activeId ? (
          <>
            <input value={title} onChange={e=>setTitle(e.target.value)} placeholder="Заголовок" style={{ width: '100%', padding: 10, fontSize: 18, marginBottom: 10 }} />
            <textarea value={body} onChange={e=>setBody(e.target.value)} style={{ width: '100%', height: '70vh', padding: 12 }} />
            <div style={{ marginTop: 8, color: '#888' }}>Автосохранение — изменения сохраняются автоматически.</div>
          </>
        ) : <div>Выберите или создайте заметку</div>}
      </div>
    </div>
  );
}
