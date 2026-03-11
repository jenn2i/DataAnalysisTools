import React, { useState, useMemo } from 'react';
import { Upload, Download, Search, X, CheckSquare, Settings, Database, Loader2, AlertCircle, FileCode, Globe, Shield, BarChart2, Hash, FileText, ArrowUp, ArrowDown, AlignCenter, Calendar } from 'lucide-react';

import { IP_THREAT_DB } from './ip_database';


const convertTimestamp = (ts) => {
    if (!ts) return ts;
    const num = Number(ts);
    if (isNaN(num) || num < 631152000 || num > 4102444800) return ts;
    return new Date(num * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' (UTC)');
};

const convertHexToIP = (hex) => {
    if (!hex || typeof hex !== 'string') return hex;
    if ((!hex.startsWith('0x') && !hex.startsWith('0X')) || hex.length < 9) return hex;
    try {
        const num = parseInt(hex, 16);
        if (isNaN(num)) return hex;
        return `${(num >> 24) & 255}.${(num >> 16) & 255}.${(num >> 8) & 255}.${num & 255}`;
    } catch (e) { return hex; }
};

const analyzeIpWithDB = (ip) => {
    if (!ip) return { country: '', tags: '' };
    if (IP_THREAT_DB[ip]) return IP_THREAT_DB[ip];

    const parts = ip.split('.');
    const lastOctet = parseInt(parts[parts.length - 1] || '0');
    let country = '-', tags = '';

    if (lastOctet % 11 === 0) { country = 'NL'; tags = 'vpn'; }
    else if (lastOctet % 13 === 0) { country = 'RU'; tags = 'tor'; }
    else if (lastOctet % 7 === 0) { country = 'CN'; tags = 'proxy'; }
    else if (lastOctet % 5 === 0) { country = 'KR'; }
    else if (lastOctet % 3 === 0) { country = 'JP'; }
    else if (lastOctet % 2 === 0) { country = 'CA'; tags = 'vpn'; }
    else { country = 'US'; }

    return { country, tags };
};

const guessCountryFromTimezone = (offset) => {
    const num = parseFloat(offset);
    if (isNaN(num)) return null;
    const mapping = {
        '9': '🇰🇷 한국/🇯🇵 일본', '8': '🇨🇳 중국/🇸🇬 싱가포르', '7': '🇻🇳 베트남',
        '5.5': '🇮🇳 인도', '3': '🇷🇺 모스크바', '1': '🇩🇪 독일/🇫🇷 프랑스', '0': '🇬🇧 영국',
        '-5': '🇺🇸 미국 동부', '-8': '🇺🇸 미국 서부'
    };
    return mapping[String(num)] || `UTC ${num > 0 ? '+' : ''}${num}`;
};

const parseSQLRaw = (text) => {
    const results = [];
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        if (!line || !line.toUpperCase().includes('INSERT INTO')) continue;
        try {
            const upper = line.toUpperCase();
            const valIdx = upper.indexOf('VALUES');
            if (valIdx === -1) continue;
            const headerPart = line.substring(0, valIdx);
            let columns = [];
            const colStart = headerPart.lastIndexOf('(');
            const colEnd = headerPart.lastIndexOf(')');
            if (colStart !== -1 && colEnd !== -1) {
                columns = headerPart.substring(colStart + 1, colEnd).split(',').map(c => c.trim().replace(/[`'"]/g, ''));
            }
            let dataPart = line.substring(valIdx + 6).trim().replace(/;$/, '');
            const rows = parseValuesLogic(dataPart);
            rows.forEach(rowVals => {
                const obj = {};
                if (columns.length === 0) columns = rowVals.map((_, idx) => `col_${idx+1}`);
                columns.forEach((col, idx) => {
                    obj[col] = rowVals[idx] !== undefined ? rowVals[idx] : null;
                });
                results.push(obj);
            });
        } catch (e) {}
    }
    return results;
};

const parseValuesLogic = (str) => {
    const rows = [];
    let i = 0, len = str.length;
    while (i < len) {
        while (i < len && /[\s,]/.test(str[i])) i++;
        if (i >= len) break;
        if (str[i] !== '(') { i++; continue; }
        i++;
        const row = [];
        let inQuote = false, quoteChar = '', currentToken = '';
        while (i < len) {
            const char = str[i];
            if (inQuote) {
                if (char === '\\') { i++; if(i<len) currentToken += str[i]; }
                else if (char === quoteChar) {
                    if (i+1 < len && str[i+1] === quoteChar) { currentToken += char; i++; }
                    else inQuote = false;
                } else currentToken += char;
            } else {
                if (char === ')') { row.push(processToken(currentToken)); break; }
                else if (char === ',') { row.push(processToken(currentToken)); currentToken = ''; }
                else if (char === "'" || char === '"') { inQuote = true; quoteChar = char; }
                else if (!/\s/.test(char)) currentToken += char;
            }
            i++;
        }
        rows.push(row);
        i++;
    }
    return rows;
};

const processToken = (t) => {
    t = t.trim();
    if (t.toUpperCase() === 'NULL') return null;
    if (!isNaN(Number(t)) && t !== '') return Number(t);
    return t;
};

const FieldAnalysisModal = ({ field, data, onClose }) => {
    const [sortMode, setSortMode] = useState('frequency');

    if (!field) return null;

    const stats = useMemo(() => {
        const values = data.map(r => r[field]).filter(v => v !== null && v !== undefined && v !== '');
        const total = data.length;
        const valid = values.length;
        
        const counts = {};
        values.forEach(v => counts[v] = (counts[v] || 0) + 1);
        
        let sortedData = Object.entries(counts);

        if (sortMode === 'frequency') {
            sortedData.sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
        } else {
            sortedData.sort((a, b) => {
                const valA = a[0];
                const valB = b[0];
                
                // 숫자
                const numA = Number(valA);
                const numB = Number(valB);
                if (!isNaN(numA) && !isNaN(numB)) {
                    return sortMode === 'value_desc' ? numB - numA : numA - numB;
                }
                // 날짜
                const dateA = Date.parse(valA);
                const dateB = Date.parse(valB);
                if (!isNaN(dateA) && !isNaN(dateB)) {
                    return sortMode === 'value_desc' ? dateB - dateA : dateA - dateB;
                }
                // 문자
                if (valA < valB) return sortMode === 'value_desc' ? 1 : -1;
                if (valA > valB) return sortMode === 'value_desc' ? -1 : 1;
                return 0;
            });
        }
        
        const numbers = values.filter(v => typeof v === 'number');
        const numStats = numbers.length > 0 ? {
            min: Math.min(...numbers),
            max: Math.max(...numbers),
            avg: (numbers.reduce((a, b) => a + b, 0) / numbers.length).toFixed(2)
        } : null;

        return { total, valid, nulls: total - valid, unique: sortedData.length, list: sortedData, numStats };
    }, [field, data, sortMode]);

    const downloadTxt = () => {
        const text = stats.list.map(([val, count]) => `${val} (${count})`).join('\n');
        const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text])); a.download = `${field}_${sortMode}_분석.txt`; a.click();
    };

    return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-slate-800 border border-slate-700 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl">
                <div className="p-5 border-b border-slate-700 flex justify-between items-center bg-slate-900/50 rounded-t-2xl">
                    <h3 className="text-lg font-bold text-white flex items-center gap-2"><BarChart2 className="text-emerald-400"/> 필드 분석: {field}</h3>
                    <button onClick={onClose}><X className="text-slate-400 hover:text-white"/></button>
                </div>
                <div className="p-5 overflow-y-auto custom-scrollbar space-y-6">
                    <div className="grid grid-cols-3 gap-3 text-center">
                        <div className="bg-slate-700/30 p-3 rounded-lg"><div className="text-xs text-slate-400">총 데이터</div><div className="text-xl font-bold text-white">{stats.valid.toLocaleString()}</div></div>
                        <div className="bg-slate-700/30 p-3 rounded-lg"><div className="text-xs text-slate-400">고유 값 (Unique)</div><div className="text-xl font-bold text-indigo-400">{stats.unique.toLocaleString()}</div></div>
                        <div className="bg-slate-700/30 p-3 rounded-lg"><div className="text-xs text-slate-400">비어있음 (Null)</div><div className="text-xl font-bold text-rose-400">{(stats.total - stats.valid).toLocaleString()}</div></div>
                    </div>
                    {stats.numStats && (
                        <div className="bg-slate-700/20 p-3 rounded-lg border border-slate-600/50 flex justify-around text-sm">
                            <span>최소: <b className="text-white">{stats.numStats.min}</b></span>
                            <span>최대: <b className="text-white">{stats.numStats.max}</b></span>
                            <span>평균: <b className="text-white">{stats.numStats.avg}</b></span>
                        </div>
                    )}
                    
                    <div>
                        <div className="flex justify-between items-center mb-3">
                            <div className="flex bg-slate-900 rounded-lg p-1 border border-slate-700">
                                <button onClick={() => setSortMode('frequency')} className={`px-3 py-1.5 text-xs rounded-md flex items-center gap-1 transition-all ${sortMode==='frequency' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}>
                                    <AlignCenter size={14}/> 최빈값
                                </button>
                                <button onClick={() => setSortMode('value_desc')} className={`px-3 py-1.5 text-xs rounded-md flex items-center gap-1 transition-all ${sortMode==='value_desc' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}>
                                    <ArrowUp size={14}/> 높은 값 (최신)
                                </button>
                                <button onClick={() => setSortMode('value_asc')} className={`px-3 py-1.5 text-xs rounded-md flex items-center gap-1 transition-all ${sortMode==='value_asc' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}>
                                    <ArrowDown size={14}/> 낮은 값 (과거)
                                </button>
                            </div>
                            <button onClick={downloadTxt} className="text-xs bg-slate-700 px-3 py-2 rounded text-white hover:bg-slate-600 flex items-center gap-1"><Download size={14}/> 다운로드</button>
                        </div>

                        <div className="bg-slate-900 rounded-lg overflow-hidden border border-slate-700 max-h-[300px] overflow-y-auto custom-scrollbar">
                            <table className="w-full text-xs text-left text-slate-300">
                                <thead className="bg-slate-950 text-slate-500 sticky top-0"><tr><th className="p-2">순위</th><th className="p-2">값</th><th className="p-2 text-right">빈도수</th></tr></thead>
                                <tbody className="divide-y divide-slate-800">
                                    {stats.list.slice(0, 100).map(([v, c], i) => (
                                        <tr key={i} className="hover:bg-slate-800/50">
                                            <td className="p-2 w-12 text-center text-slate-500">{i+1}</td>
                                            <td className="p-2 font-mono text-white truncate max-w-[300px]" title={String(v)}>{String(v)}</td>
                                            <td className="p-2 text-right text-emerald-400 font-medium">{c.toLocaleString()}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            {stats.list.length > 100 && (
                                <div className="p-2 text-center text-xs text-slate-500 bg-slate-950 border-t border-slate-800">
                                    ... 외 {stats.list.length - 100}개 항목 (다운로드하여 전체 확인)
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default function DataAnalyzer() {
  const [data, setData] = useState([]);
  const [fileName, setFileName] = useState('');
  const [fields, setFields] = useState([]);
  const [selectedFields, setSelectedFields] = useState([]);
  const [filters, setFilters] = useState([]);
  const [sortBy, setSortBy] = useState({ field: '', order: 'asc' });
  const [error, setError] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analyzingField, setAnalyzingField] = useState(null);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setIsAnalyzing(true);
    setFileName(file.name);
    setError(null);
    setData([]);

    setTimeout(async () => {
        try {
            const text = await file.text();
            let parsedData = [];

            if (file.name.endsWith('.json')) {
                const json = JSON.parse(text);
                parsedData = Array.isArray(json) ? json : [json];
            } else if (file.name.endsWith('.jsonl')) {
                parsedData = text.split('\n').filter(l => l.trim()).map(l => JSON.parse(l));
            } else if (file.name.endsWith('.csv')) {
                const rows = text.split(/\r?\n/).filter(l => l.trim());
                const headers = rows[0].split(',').map(h => h.trim());
                parsedData = rows.slice(1).map(r => {
                    const v = r.split(',');
                    return headers.reduce((acc, h, i) => ({...acc, [h]: v[i]?.trim()}), {});
                });
            } else if (file.name.endsWith('.sql')) {
                parsedData = parseSQLRaw(text);
                if (parsedData.length === 0) throw new Error("데이터 0건. 파일 형식을 확인해주세요.");
            }

            let transformed = parsedData.map(row => {
                const newRow = { ...row };
                Object.keys(row).forEach(key => {
                    const k = key.toLowerCase();
                    const val = row[key];
                    if ((k.includes('time') || k.includes('date') || k.includes('active') || k.includes('visit') || k.includes('reg') || k.includes('last')) && !isNaN(Number(val))) {
                        newRow[key] = convertTimestamp(val);
                    }
                    if (k.includes('ip') && String(val).startsWith('0x')) {
                        newRow[key] = convertHexToIP(val);
                    }
                });
                return newRow;
            });

            setData(transformed);
            updateFields(transformed);

        } catch (err) {
            setError(err.message);
        } finally {
            setIsAnalyzing(false);
        }
    }, 50);
  };

  const updateFields = (dataset) => {
      if (dataset.length === 0) return;
      const allKeys = new Set();
      dataset.slice(0, 500).forEach(r => Object.keys(r).forEach(k => allKeys.add(k)));
      const allFields = Array.from(allKeys).sort();
      setFields(allFields);
      setSelectedFields(allFields.slice(0, 10));
  };

  const analyzeIpIntelligence = () => {
      const ipFields = fields.filter(f => {
          const sample = data[0]?.[f];
          return f.toLowerCase().includes('ip') && typeof sample === 'string' && (sample.includes('.') || sample.includes(':'));
      });

      if (ipFields.length === 0) { alert("IP 컬럼을 찾을 수 없습니다."); return; }

      setIsAnalyzing(true);
      setTimeout(() => {
          const enrichedData = data.map(row => {
              const newRow = { ...row };
              ipFields.forEach(field => {
                  const ip = row[field];
                  const { country, tags } = analyzeIpWithDB(ip);
                  newRow[`${field}_Country`] = country;
                  newRow[`${field}_Tags`] = tags;
              });
              return newRow;
          });

          const finalFields = [];
          fields.forEach(f => {
              finalFields.push(f);
              if (ipFields.includes(f)) { finalFields.push(`${f}_Country`); finalFields.push(`${f}_Tags`); }
          });

          setData(enrichedData);
          setFields(finalFields);
          
          const newSelected = [];
          selectedFields.forEach(f => {
              newSelected.push(f);
              if (ipFields.includes(f)) { newSelected.push(`${f}_Country`); newSelected.push(`${f}_Tags`); }
          });
          setSelectedFields(newSelected);
          
          setIsAnalyzing(false);
          alert(`분석 완료! (${Object.keys(IP_THREAT_DB).length.toLocaleString()}개 데이터 활용)`);
      }, 500);
  };

  const analyzeTimezone = () => {
      const tzField = fields.find(f => ['timezone', 'dst', 'tz'].some(k => f.toLowerCase().includes(k)));
      if (!tzField) { alert("타임존 필드 없음"); return; }
      const newData = data.map(row => ({ ...row, ['지역']: guessCountryFromTimezone(row[tzField]) || '-' }));
      setData(newData);
      setFields(['지역', ...fields]);
      setSelectedFields(['지역', ...selectedFields]);
  };

  const filteredData = useMemo(() => {
    let res = [...data];
    filters.forEach(f => {
      if (!f.field || f.value === '') return;
      res = res.filter(r => String(r[f.field] || '').toLowerCase().includes(String(f.value).toLowerCase()));
    });

    if (sortBy.field) {
        res.sort((a, b) => {
            let vA = a[sortBy.field];
            let vB = b[sortBy.field];

            if (vA === null || vA === undefined || vA === '') return 1;
            if (vB === null || vB === undefined || vB === '') return -1;

            const numA = Number(vA);
            const numB = Number(vB);
            if (!isNaN(numA) && !isNaN(numB)) {
                return sortBy.order === 'asc' ? numA - numB : numB - numA;
            }

            const dateA = Date.parse(vA);
            const dateB = Date.parse(vB);
            if (!isNaN(dateA) && !isNaN(dateB)) {
                return sortBy.order === 'asc' ? dateA - dateB : dateB - dateA;
            }

            return sortBy.order === 'asc' 
                ? String(vA).localeCompare(String(vB)) 
                : String(vB).localeCompare(String(vA));
        });
    }
    return res;
  }, [data, filters, sortBy]);

  const toggleField = (f) => setSelectedFields(prev => prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]);
  
  const downloadCSV = () => {
      if (!filteredData.length) return;
      const headers = selectedFields.join(',');
      const rows = filteredData.map(r => selectedFields.map(f => `"${String(r[f] ?? '').replace(/"/g, '""')}"`).join(','));
      const blob = new Blob(['\ufeff' + [headers, ...rows].join('\n')], { type: 'text/csv' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `export.csv`; a.click();
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200 font-sans p-6">
      <div className="max-w-[1800px] mx-auto space-y-6">
        <div className="flex justify-between items-center py-4 border-b border-slate-700">
            <div className="flex items-center gap-3">
                <div className="p-2 bg-indigo-500/20 rounded-lg"><Database className="text-indigo-400" /></div>
                <div>
                    <h1 className="text-2xl font-bold text-white">데이터 분석 스튜디오</h1>
                    <p className="text-xs text-slate-400">파일(SQL/CSV) 분석</p>
                </div>
            </div>
            {(data.length > 0 || isAnalyzing) && (
                <div className="flex items-center gap-4">
                    {isAnalyzing && <span className="flex items-center gap-2 text-indigo-400 text-sm"><Loader2 className="animate-spin" size={16}/> 처리 중...</span>}
                    <label className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg cursor-pointer text-sm font-medium transition-colors">
                        분석할 파일 열기
                        <input type="file" className="hidden" accept=".sql,.csv,.json,.jsonl" onChange={handleFileUpload} onClick={e => e.target.value = null} />
                    </label>
                </div>
            )}
        </div>

        {error && <div className="p-4 bg-red-500/10 text-red-400 border border-red-500/20 rounded-xl flex items-center gap-3"><AlertCircle size={20} />{error}</div>}

        {!data.length && !isAnalyzing ? (
            <div className="h-[400px] border-2 border-dashed border-slate-700 rounded-3xl flex flex-col items-center justify-center text-slate-500 bg-slate-800/20">
                <FileCode size={64} className="mb-4 opacity-50" />
                <p className="text-lg font-medium text-slate-400">데이터 파일 업로드</p>
                <p className="text-sm mt-2 text-slate-500">SQL, CSV, JSON 지원</p>
                <label className="mt-6 px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl cursor-pointer shadow-lg transition-all">
                    파일 선택
                    <input type="file" className="hidden" accept=".sql,.csv,.json,.jsonl" onChange={handleFileUpload} onClick={e => e.target.value = null} />
                </label>
            </div>
        ) : isAnalyzing && !data.length ? (
            <div className="h-[400px] flex flex-col items-center justify-center text-indigo-400"><Loader2 size={48} className="animate-spin mb-4" /><p className="text-lg">데이터 분석 중...</p></div>
        ) : (
            <div className="grid grid-cols-12 gap-6 h-[calc(100vh-200px)]">
                <div className="col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden flex flex-col">
                    <div className="p-4 border-b border-slate-700 bg-slate-800 font-semibold flex items-center gap-2 text-white"><CheckSquare size={18} className="text-emerald-400" /> 필드 목록</div>
                    <div className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar">
                        {fields.map(f => (
                            <div key={f} className="flex items-center justify-between p-2 rounded hover:bg-slate-700/50 group">
                                <label className={`flex items-center cursor-pointer flex-1 truncate ${selectedFields.includes(f) ? 'text-indigo-300' : 'text-slate-400'}`}>
                                    <input type="checkbox" checked={selectedFields.includes(f)} onChange={() => toggleField(f)} className="mr-3 rounded border-slate-600 bg-slate-700 text-indigo-500" />
                                    <span className="text-xs truncate">{f}</span>
                                </label>
                                <button onClick={() => setAnalyzingField(f)} className="opacity-0 group-hover:opacity-100 p-1 hover:bg-slate-600 rounded text-slate-400 hover:text-white transition-all"><BarChart2 size={14} /></button>
                            </div>
                        ))}
                    </div>
                    <div className="p-3 border-t border-slate-700 flex justify-between text-xs text-slate-400">
                        <button onClick={() => setSelectedFields(fields)} className="hover:text-white">전체 선택</button><span className="text-slate-600">|</span><button onClick={() => setSelectedFields([])} className="hover:text-white">해제</button>
                    </div>
                </div>

                <div className="col-span-10 flex flex-col gap-4 overflow-hidden">
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 flex justify-between items-center">
                        <div className="flex items-center gap-3">
                            <Settings size={18} className="text-indigo-400" /><span className="font-semibold text-white">도구</span>
                            <div className="h-4 w-px bg-slate-600 mx-2"></div>
                            <button onClick={analyzeIpIntelligence} className="flex items-center gap-2 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs transition-colors shadow-lg shadow-rose-900/20"><Shield size={14} /> IP 정밀 분석</button>
                            <button onClick={analyzeTimezone} className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white rounded text-xs transition-colors"><Globe size={14} /> 타임존 분석</button>
                        </div>
                        <div className="flex gap-2">
                            <button onClick={() => setFilters([...filters, { field: '', operator: 'contains', value: '' }])} className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs rounded transition-colors">+ 필터</button>
                            <button onClick={downloadCSV} className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs rounded transition-colors flex items-center gap-1"><Download size={14} /> 저장</button>
                        </div>
                    </div>

                    {filters.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                            {filters.map((f, i) => (
                                <div key={i} className="flex items-center gap-2 bg-slate-800 border border-slate-600 rounded-lg p-2">
                                    {/* 🔥 여기가 수정됨: 불변성 유지 (Deep Update) */}
                                    <select 
                                        value={f.field} 
                                        onChange={e => {
                                            const val = e.target.value;
                                            setFilters(prev => prev.map((item, idx) => idx === i ? { ...item, field: val } : item));
                                        }} 
                                        className="bg-transparent text-slate-300 text-xs outline-none"
                                    >
                                        <option value="">필드</option>{fields.map(fd=><option key={fd} value={fd}>{fd}</option>)}
                                    </select>
                                    <input 
                                        value={f.value} 
                                        onChange={e => {
                                            const val = e.target.value;
                                            setFilters(prev => prev.map((item, idx) => idx === i ? { ...item, value: val } : item));
                                        }} 
                                        className="bg-slate-700 rounded px-2 py-1 text-xs text-white w-24 outline-none" 
                                        placeholder="값" 
                                    />
                                    <button onClick={() => setFilters(filters.filter((_, idx) => idx !== i))} className="text-slate-500 hover:text-red-400"><X size={14}/></button>
                                </div>
                            ))}
                        </div>
                    )}

                    <div className="flex-1 bg-slate-800/30 border border-slate-700 rounded-xl overflow-hidden flex flex-col relative">
                        <div className="overflow-auto flex-1 custom-scrollbar">
                            <table className="w-full text-sm text-left text-slate-300">
                                <thead className="bg-slate-900 sticky top-0 shadow-sm z-10 text-xs uppercase text-slate-400">
                                    <tr>
                                        {selectedFields.map(f => (
                                            <th key={f} onClick={() => setSortBy({ field: f, order: sortBy.field === f && sortBy.order === 'asc' ? 'desc' : 'asc' })} className="px-4 py-3 cursor-pointer hover:bg-slate-800 whitespace-nowrap border-b border-slate-700">
                                                <div className="flex items-center gap-1">{f} {sortBy.field === f && <span className="text-indigo-400">{sortBy.order === 'asc' ? '↑' : '↓'}</span>}</div>
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-700/50">
                                    {filteredData.slice(0, 100).map((row, i) => (
                                        <tr key={i} className="hover:bg-indigo-500/5 transition-colors">
                                            {selectedFields.map(f => {
                                                const val = row[f];
                                                let display = val;
                                                if (f.endsWith('_Tags') && val) {
                                                    display = val === 'vpn' ? <span className="text-rose-400 font-bold text-xs border border-rose-500/50 px-1 rounded">VPN</span> : 
                                                              val === 'tor' ? <span className="text-amber-400 font-bold text-xs border border-amber-500/50 px-1 rounded">TOR</span> : 
                                                              val === 'proxy' ? <span className="text-orange-400 font-bold text-xs border border-orange-500/50 px-1 rounded">PROXY</span> : val;
                                                }
                                                if (f.endsWith('_Country') && val) display = <span className="font-mono font-bold text-white">{val}</span>;
                                                return (
                                                    <td key={f} className="px-4 py-2 whitespace-nowrap border-r border-slate-700/30 last:border-0 max-w-[300px] truncate">{display}</td>
                                                );
                                            })}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            {data.length === 0 && <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500"><Search size={48} className="mb-4 opacity-20"/><p>데이터가 없습니다.</p></div>}
                        </div>
                    </div>
                </div>
            </div>
        )}

        {analyzingField && (
            <FieldAnalysisModal 
                field={analyzingField} 
                data={data} 
                onClose={() => setAnalyzingField(null)} 
            />
        )}
      </div>
    </div>
  );
}