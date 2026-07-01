import React, { useState, useEffect, useCallback, useMemo } from 'react';

// Популярные уязвимые пароли и паттерны для локальной базы анализатора
const COMMON_PASSWORDS = [
  '123456', 'password', '123456789', '12345678', '12345', 'qwerty', 
  '1234567', 'password123', '123123', 'admin', '111111', 'sunshine', 
  'iloveyou', 'football', 'administrator', 'welcome', 'master', 'password1'
];

const KEYBOARD_PATTERNS = [
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  'йцукенгшщзхъ', 'фывапролджэ', 'ячсмитьбю',
  '1234567890'
];

export default function App() {
  // Состояния для генератора паролей
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [length, setLength] = useState(16);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [excludeSimilar, setExcludeSimilar] = useState(false);
  const [copied, setCopied] = useState(false);

  // Состояния для анализатора паролей
  const [inputPassword, setInputPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // История сгенерированных паролей (хранится в сессии приложения)
  const [history, setHistory] = useState([]);

  // Уведомления (тосты)
  const [toastMessage, setToastMessage] = useState(null);

  // Функция показа кастомных уведомлений
  const showToast = (message, type = 'success') => {
    setToastMessage({ message, type });
    setTimeout(() => {
      setToastMessage(null);
    }, 3000);
  };

  // Метод безопасного копирования в буфер обмена для iframe окружений
  const copyToClipboard = (text) => {
    try {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.left = '-9999px';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      
      setCopied(true);
      showToast('Пароль успешно скопирован в буфер обмена!');
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      showToast('Не удалось скопировать пароль автоматически', 'error');
    }
  };

  // Логика генерации пароля
  const generatePassword = useCallback(() => {
    let lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
    let uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let numberChars = '0123456789';
    let symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (excludeSimilar) {
      // Исключаем неоднозначные символы: i, l, 1, L, o, 0, O, I, |
      lowercaseChars = lowercaseChars.replace(/[ilo]/g, '');
      uppercaseChars = uppercaseChars.replace(/[ILO]/g, '');
      numberChars = numberChars.replace(/[01]/g, '');
      symbolChars = symbolChars.replace(/[|]/g, '');
    }

    let charPool = '';
    let guaranteedChars = [];

    if (includeLowercase && lowercaseChars) {
      charPool += lowercaseChars;
      guaranteedChars.push(lowercaseChars[Math.floor(Math.random() * lowercaseChars.length)]);
    }
    if (includeUppercase && uppercaseChars) {
      charPool += uppercaseChars;
      guaranteedChars.push(uppercaseChars[Math.floor(Math.random() * uppercaseChars.length)]);
    }
    if (includeNumbers && numberChars) {
      charPool += numberChars;
      guaranteedChars.push(numberChars[Math.floor(Math.random() * numberChars.length)]);
    }
    if (includeSymbols && symbolChars) {
      charPool += symbolChars;
      guaranteedChars.push(symbolChars[Math.floor(Math.random() * symbolChars.length)]);
    }

    if (charPool === '') {
      showToast('Выберите хотя бы один набор символов!', 'error');
      return;
    }

    let result = [...guaranteedChars];
    const remainingLength = length - guaranteedChars.length;

    for (let i = 0; i < remainingLength; i++) {
      const randomIndex = Math.floor(Math.random() * charPool.length);
      result.push(charPool[randomIndex]);
    }

    // Перемешиваем результат для большей случайности
    for (let i = result.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [result[i], result[j]] = [result[j], result[i]];
    }

    const finalPassword = result.join('');
    setGeneratedPassword(finalPassword);
    
    // Добавление в историю
    setHistory(prev => [finalPassword, ...prev.slice(0, 4)]);
  }, [length, includeUppercase, includeLowercase, includeNumbers, includeSymbols, excludeSimilar]);

  // Генерируем пароль при первой загрузке компонента
  useEffect(() => {
    generatePassword();
  }, []);

  // Кастомный анализатор паролей (энтропия + эвристика)
  const analysis = useMemo(() => {
    const password = inputPassword;
    if (!password) {
      return {
        score: 0,
        label: 'Пусто',
        color: 'bg-slate-200',
        textColor: 'text-slate-400',
        entropy: 0,
        checks: [],
        crackTime: 'мгновенно'
      };
    }

    let score = 0;
    const checks = [];
    let poolSize = 0;

    const hasLower = /[a-zа-я]/.test(password);
    const hasUpper = /[A-ZА-Я]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9а-яА-ЯёЁ]/.test(password);

    // Определение размера пула возможных символов
    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasDigit) poolSize += 10;
    if (hasSpecial) poolSize += 32;

    // Расчет энтропии (Шеннона)
    const entropy = Math.round(password.length * Math.log2(poolSize || 1));

    // Проверки требований безопасности
    if (password.length >= 12) {
      checks.push({ text: 'Длина пароля отличная (12+ символов)', positive: true });
      score += 1;
    } else if (password.length >= 8) {
      checks.push({ text: 'Минимальная длина соблюдена (8+ символов)', positive: true });
      score += 0.5;
    } else {
      checks.push({ text: 'Пароль слишком короткий (менее 8 символов)', positive: false });
    }

    const varietyCount = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
    if (varietyCount >= 4) {
      checks.push({ text: 'Используются все типы символов', positive: true });
      score += 1.5;
    } else if (varietyCount >= 3) {
      checks.push({ text: 'Хорошее разнообразие символов', positive: true });
      score += 1;
    } else {
      checks.push({ text: 'Мало разнообразия (добавьте цифры, спецсимволы или разный регистр)', positive: false });
    }

    // Проверка на популярные пароли
    const isCommon = COMMON_PASSWORDS.includes(password.toLowerCase());
    if (isCommon) {
      checks.push({ text: 'Этот пароль входит в список самых популярных и взламывается мгновенно', positive: false });
      score = 0;
    }

    // Проверка на клавиатурные последовательности
    let hasKeyboardSeq = false;
    for (const pat of KEYBOARD_PATTERNS) {
      for (let i = 0; i < pat.length - 3; i++) {
        const sub = pat.substring(i, i + 4);
        if (password.toLowerCase().includes(sub)) {
          hasKeyboardSeq = true;
          break;
        }
      }
    }
    if (hasKeyboardSeq) {
      checks.push({ text: 'Обнаружена клавиатурная последовательность (например, "qwerty" или "1234")', positive: false });
      score = Math.max(0, score - 1);
    }

    // Проверка на повторяющиеся символы подряд (например, "aaa", "111")
    const hasRepeats = /(.)\1\1/.test(password);
    if (hasRepeats) {
      checks.push({ text: 'Присутствуют повторяющиеся подряд символы', positive: false });
      score = Math.max(0, score - 0.5);
    }

    // Итоговая оценка по шкале от 0 до 4
    let finalScore = 0;
    if (entropy > 80 && score >= 2) finalScore = 4; // Очень сильный
    else if (entropy > 55 && score >= 1.5) finalScore = 3; // Сильный
    else if (entropy > 35 && score >= 1) finalScore = 2; // Средний
    else if (password.length > 0) finalScore = 1; // Слабый

    if (isCommon) finalScore = 0;

    // Расчет времени взлома (предполагаем скорость перебора 10 миллиардов комбинаций в секунду - средний GPU кластер)
    const guesses = Math.pow(poolSize || 1, password.length);
    const hashesPerSecond = 1e10; 
    const secondsToCrack = guesses / hashesPerSecond;

    let crackTime = '';
    if (secondsToCrack < 1) {
      crackTime = 'меньше секунды';
    } else if (secondsToCrack < 60) {
      crackTime = `${Math.round(secondsToCrack)} сек.`;
    } else if (secondsToCrack < 3600) {
      crackTime = `${Math.round(secondsToCrack / 60)} мин.`;
    } else if (secondsToCrack < 86400) {
      crackTime = `${Math.round(secondsToCrack / 3600)} ч.`;
    } else if (secondsToCrack < 31536000) {
      crackTime = `${Math.round(secondsToCrack / 86400)} дн.`;
    } else if (secondsToCrack < 3153600000) {
      crackTime = `${Math.round(secondsToCrack / 31536000)} лет`;
    } else {
      crackTime = 'века (более 100 лет)';
    }

    // Маппинг визуальных стилей оценок
    const ratingConfig = [
      { label: 'Крайне ненадежный', color: 'bg-rose-500', textColor: 'text-rose-500' },
      { label: 'Слабый пароль', color: 'bg-orange-500', textColor: 'text-orange-500' },
      { label: 'Средняя стойкость', color: 'bg-amber-500', textColor: 'text-amber-500' },
      { label: 'Надежный пароль', color: 'bg-emerald-500', textColor: 'text-emerald-500' },
      { label: 'Абсолютная защита', color: 'bg-indigo-600', textColor: 'text-indigo-600' }
    ];

    return {
      score: finalScore,
      label: ratingConfig[finalScore].label,
      color: ratingConfig[finalScore].color,
      textColor: ratingConfig[finalScore].textColor,
      entropy,
      checks,
      crackTime
    };
  }, [inputPassword]);

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex items-center justify-center p-4 md:p-8 font-sans antialiased selection:bg-indigo-500 selection:text-white">
      
      {/* Кастомный тост уведомлений */}
      {toastMessage && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-xl shadow-2xl transition-all transform duration-300 translate-y-0 ${
          toastMessage.type === 'error' ? 'bg-rose-600 text-white' : 'bg-slate-800 border border-indigo-500/30 text-emerald-400'
        }`}>
          {toastMessage.type === 'error' ? (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          )}
          <span className="text-sm font-medium">{toastMessage.message}</span>
        </div>
      )}

      <div className="max-w-5xl w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Хедер приложения на всю ширину */}
        <div className="lg:col-span-12 text-center lg:text-left mb-2">
          <div className="inline-flex items-center gap-3 bg-indigo-500/10 border border-indigo-500/20 px-4 py-2 rounded-full mb-4">
            <span className="w-2.5 h-2.5 bg-indigo-500 rounded-full animate-ping"></span>
            <span className="text-xs text-indigo-400 font-semibold tracking-wider uppercase">Инструмент Безопасности v2.5</span>
          </div>
          <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-100 to-indigo-400">
            Генератор & Анализатор Паролей
          </h1>
          <p className="text-slate-400 mt-2 text-sm md:text-base max-w-2xl">
            Создавайте криптостойкие пароли в один клик и проверяйте надёжность своих текущих ключей с помощью умного эвристического анализатора.
          </p>
        </div>

        {/* ЛЕВАЯ КОЛОНКА: Генератор паролей */}
        <div className="lg:col-span-7 bg-slate-800/50 backdrop-blur-md border border-slate-700/60 rounded-3xl p-6 md:p-8 shadow-xl flex flex-col justify-between h-full">
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold flex items-center gap-2">
                <svg className="w-5 h-5 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 00-2 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                Генератор Паролей
              </h2>
              <button 
                onClick={generatePassword} 
                className="text-slate-400 hover:text-indigo-400 transition-colors p-2 rounded-lg hover:bg-slate-700/50"
                title="Сгенерировать заново"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 15H19" />
                </svg>
              </button>
            </div>

            {/* Вывод сгенерированного пароля */}
            <div className="bg-slate-900/80 border border-slate-700 rounded-2xl p-4 md:p-5 flex items-center justify-between gap-4 mb-6 relative group overflow-hidden">
              <div className="font-mono text-lg md:text-xl text-indigo-300 break-all select-all tracking-wider font-semibold z-10">
                {generatedPassword || 'Нажмите генерацию...'}
              </div>
              <button
                onClick={() => copyToClipboard(generatedPassword)}
                className={`p-3 rounded-xl transition-all flex-shrink-0 z-10 ${
                  copied 
                    ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/20' 
                    : 'bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 border border-slate-700'
                }`}
                title="Копировать"
              >
                {copied ? (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                  </svg>
                )}
              </button>
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-indigo-500/5 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-1000"></div>
            </div>

            {/* Слайдер длины */}
            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-slate-300">Длина пароля:</span>
                <span className="text-sm font-bold text-indigo-400 font-mono bg-indigo-500/10 px-2.5 py-1 rounded-md border border-indigo-500/20">
                  {length} симв.
                </span>
              </div>
              <input
                type="range"
                min="8"
                max="64"
                value={length}
                onChange={(e) => setLength(parseInt(e.target.value))}
                className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-indigo-500"
              />
              <div className="flex justify-between text-xs text-slate-500 mt-1 font-mono">
                <span>8</span>
                <span>24</span>
                <span>40</span>
                <span>56</span>
                <span>64</span>
              </div>
            </div>

            {/* Настройки параметров */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-8">
              <label className="flex items-center gap-3 bg-slate-800/40 border border-slate-700/50 p-3.5 rounded-xl cursor-pointer hover:bg-slate-800/80 hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={includeUppercase}
                  onChange={(e) => setIncludeUppercase(e.target.checked)}
                  className="w-4 h-4 rounded text-indigo-600 bg-slate-900 border-slate-700 focus:ring-indigo-500 focus:ring-offset-0 focus:ring-2"
                />
                <span className="text-sm text-slate-300">ПРОПИСНЫЕ (A-Z)</span>
              </label>

              <label className="flex items-center gap-3 bg-slate-800/40 border border-slate-700/50 p-3.5 rounded-xl cursor-pointer hover:bg-slate-800/80 hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={includeLowercase}
                  onChange={(e) => setIncludeLowercase(e.target.checked)}
                  className="w-4 h-4 rounded text-indigo-600 bg-slate-900 border-slate-700 focus:ring-indigo-500 focus:ring-offset-0 focus:ring-2"
                />
                <span className="text-sm text-slate-300">строчные (a-z)</span>
              </label>

              <label className="flex items-center gap-3 bg-slate-800/40 border border-slate-700/50 p-3.5 rounded-xl cursor-pointer hover:bg-slate-800/80 hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={includeNumbers}
                  onChange={(e) => setIncludeNumbers(e.target.checked)}
                  className="w-4 h-4 rounded text-indigo-600 bg-slate-900 border-slate-700 focus:ring-indigo-500 focus:ring-offset-0 focus:ring-2"
                />
                <span className="text-sm text-slate-300">Цифры (0-9)</span>
              </label>

              <label className="flex items-center gap-3 bg-slate-800/40 border border-slate-700/50 p-3.5 rounded-xl cursor-pointer hover:bg-slate-800/80 hover:border-slate-600 transition-all">
                <input
                  type="checkbox"
                  checked={includeSymbols}
                  onChange={(e) => setIncludeSymbols(e.target.checked)}
                  className="w-4 h-4 rounded text-indigo-600 bg-slate-900 border-slate-700 focus:ring-indigo-500 focus:ring-offset-0 focus:ring-2"
                />
                <span className="text-sm text-slate-300">Спецсимволы (#$&)</span>
              </label>

              <label className="sm:col-span-2 flex items-center gap-3 bg-indigo-950/20 border border-indigo-900/30 p-3.5 rounded-xl cursor-pointer hover:bg-indigo-950/40 hover:border-indigo-800/50 transition-all">
                <input
                  type="checkbox"
                  checked={excludeSimilar}
                  onChange={(e) => setExcludeSimilar(e.target.checked)}
                  className="w-4 h-4 rounded text-indigo-600 bg-slate-900 border-slate-700 focus:ring-indigo-500 focus:ring-offset-0 focus:ring-2"
                />
                <div>
                  <span className="text-sm font-semibold text-indigo-300 block">Исключить похожие символы</span>
                  <span className="text-xs text-slate-400">Удаляет двусмысленные знаки: i, l, o, O, 0, 1</span>
                </div>
              </label>
            </div>
          </div>

          <div>
            <button
              onClick={generatePassword}
              className="w-full bg-gradient-to-r from-indigo-500 to-indigo-600 hover:from-indigo-600 hover:to-indigo-700 text-white font-bold py-4 px-6 rounded-2xl shadow-lg shadow-indigo-500/20 active:scale-[0.98] transition-all flex items-center justify-center gap-2 text-base"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              Сгенерировать пароль
            </button>

            {/* Секция истории последних генераций */}
            {history.length > 0 && (
              <div className="mt-6 pt-6 border-t border-slate-700/50">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block mb-3">Предыдущие пароли</span>
                <div className="flex flex-wrap gap-2">
                  {history.map((pw, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setGeneratedPassword(pw);
                        showToast('Пароль восстановлен из истории!');
                      }}
                      className="bg-slate-800/70 hover:bg-slate-700/50 border border-slate-700 text-slate-400 hover:text-slate-200 font-mono text-xs py-1.5 px-3 rounded-lg transition-colors truncate max-w-[150px]"
                      title="Использовать этот пароль"
                    >
                      {pw}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ПРАВАЯ КОЛОНКА: Анализатор стойкости */}
        <div className="lg:col-span-5 bg-slate-800/50 backdrop-blur-md border border-slate-700/60 rounded-3xl p-6 md:p-8 shadow-xl flex flex-col justify-between h-full">
          <div>
            <h2 className="text-xl font-bold flex items-center gap-2 mb-6">
              <svg className="w-5 h-5 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              Анализатор Стойкости
            </h2>

            {/* Ввод пароля для проверки */}
            <div className="mb-6 relative">
              <label className="text-sm font-medium text-slate-300 block mb-2">Проверить пароль на надежность:</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={inputPassword}
                  onChange={(e) => setInputPassword(e.target.value)}
                  placeholder="Введите пароль..."
                  className="w-full bg-slate-900/80 border border-slate-700 rounded-2xl py-3.5 pl-4 pr-12 font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white transition-colors p-1"
                >
                  {showPassword ? (
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.5 3.5M9 9l.5.5m2.77 2.77l.73.73M21 21l-3.5-3.5" />
                    </svg>
                  ) : (
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {/* Метрики и результаты */}
            {inputPassword ? (
              <div className="space-y-6">
                {/* Индикатор прогресса (Стойкость) */}
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Уровень защиты</span>
                    <span className={`text-sm font-bold ${analysis.textColor}`}>{analysis.label}</span>
                  </div>
                  {/* Шкала силы пароля */}
                  <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden flex gap-1">
                    {[0, 1, 2, 3].map((step) => (
                      <div
                        key={step}
                        className={`h-full flex-1 rounded-full transition-all duration-500 ${
                          step <= analysis.score ? analysis.color : 'bg-slate-700/40'
                        }`}
                      />
                    ))}
                  </div>
                </div>

                {/* Блок ключевых показателей */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-900/60 border border-slate-700/50 p-4 rounded-2xl">
                    <span className="text-xs text-slate-500 block mb-1">Время на взлом:</span>
                    <span className="font-semibold text-slate-200 text-sm md:text-base break-words">
                      ~ {analysis.crackTime}
                    </span>
                  </div>
                  <div className="bg-slate-900/60 border border-slate-700/50 p-4 rounded-2xl">
                    <span className="text-xs text-slate-500 block mb-1">Энтропия (бит):</span>
                    <span className="font-mono font-semibold text-indigo-400 text-base md:text-lg">
                      {analysis.entropy}
                    </span>
                  </div>
                </div>

                {/* Список рекомендаций / чеков */}
                <div>
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-3">Результаты проверки</span>
                  <ul className="space-y-2.5">
                    {analysis.checks.map((check, index) => (
                      <li key={index} className="flex items-start gap-3 text-xs md:text-sm">
                        {check.positive ? (
                          <svg className="w-5 h-5 text-emerald-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        ) : (
                          <svg className="w-5 h-5 text-rose-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        )}
                        <span className={check.positive ? 'text-slate-300' : 'text-slate-400'}>{check.text}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              // Состояние ожидания ввода
              <div className="text-center py-12 border-2 border-dashed border-slate-700/50 rounded-2xl flex flex-col items-center justify-center">
                <svg className="w-12 h-12 text-slate-600 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
                <p className="text-sm text-slate-500 max-w-[250px] mx-auto">
                  Введите пароль в поле выше для запуска динамической оценки стойкости
                </p>
              </div>
            )}
          </div>

          {/* Информационная плашка внизу */}
          <div className="mt-8 pt-6 border-t border-slate-700/50 text-xs text-slate-500">
            Оценка производится локально в браузере. Данные не передаются на сторонние сервера, обеспечивая максимальную конфиденциальность.
          </div>
        </div>
            <div className="lg:col-span-12 text-center text-xs text-slate-600 mt-8">
  © {new Date().getFullYear()} MySecurePass. Все права защищены. Создано с 💻 [Ваше Имя].
</div>
      </div>
      {/* <div className="lg:col-span-12 text-center text-xs text-slate-600 mt-8">
  © {new Date().getFullYear()} MySecurePass. Все права защищены. Создано с 💻 Adil.
</div> */}
    </div>
    
  );
}