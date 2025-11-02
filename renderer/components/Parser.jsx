import React, { useState } from 'react';

export default function Parser() {
  const [text, setText] = useState('');
  const [key1, setKey1] = useState('');
  const [key2, setKey2] = useState('');
  const [result, setResult] = useState('');

  const handleParse = () => {
    if (!key1 && !key2) {
      setResult('Введите хотя бы одно ключевое слово');
      return;
    }

    let highlighted = text;
    [key1, key2].forEach((key) => {
      if (key) {
        const regex = new RegExp(`(${key})`, 'gi');
        highlighted = highlighted.replace(regex, '<mark style="background:lime;color:black">$1</mark>');
      }
    });

    setResult(highlighted);
  };

  return (
    <div className="p-6 space-y-4">
      <h2 className="text-xl font-bold">Парсер лога</h2>

      <input
        className="border p-2 rounded w-full"
        placeholder="Ключевое слово 1"
        value={key1}
        onChange={(e) => setKey1(e.target.value)}
      />
      <input
        className="border p-2 rounded w-full"
        placeholder="Ключевое слово 2"
        value={key2}
        onChange={(e) => setKey2(e.target.value)}
      />

      <textarea
        className="border p-2 rounded w-full h-40"
        placeholder="Вставь сюда лог..."
        value={text}
        onChange={(e) => setText(e.target.value)}
      />

      <button
        onClick={handleParse}
        className="bg-blue-600 text-white px-4 py-2 rounded"
      >
        Проверить
      </button>

      <div
        className="border p-3 rounded bg-gray-100 overflow-auto"
        style={{ whiteSpace: 'pre-wrap' }}
        dangerouslySetInnerHTML={{ __html: result }}
      />
    </div>
  );
}
