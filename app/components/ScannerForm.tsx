"use client";

import React, { useState, useRef } from "react";
import axios from "axios";
import { Upload, Loader2, CheckCircle, AlertCircle, X, FileText } from "lucide-react";

interface ScannerFormProps {
  endpoint: string;
  fileLabel?: string;
  acceptedFileTypes?: string;
}

export default function ScannerForm({ 
  endpoint, 
  fileLabel = "Upload File", 
  acceptedFileTypes = "*"
}: ScannerFormProps) {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (file: File) => {
    setError(null);
    setResult(null);
    setFile(file);
    
    // Create preview for image files
    if (file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setPreview(e.target?.result as string);
      };
      reader.readAsDataURL(file);
    } else {
      setPreview(null);
    }
  };

  const clearFile = () => {
    setFile(null);
    setPreview(null);
    setResult(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSubmit = async () => {
    if (!file) {
      setError("Please select a file first");
      return;
    }
    
    setLoading(true);
    setResult(null);
    setError(null);
    
    const formData = new FormData();
    formData.append("file", file);
    
    try {
      const res = await axios.post(endpoint, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(res.data);
    } catch (err: any) {
      console.error("Scanning error:", err);
      setError(err.response?.data?.detail || err.message || "An error occurred during scanning");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-xl mx-auto">
      {/* Drop zone */}
      <div
        className={`
          relative border-2 border-dashed rounded-xl mb-4 transition-all duration-300
          ${dragActive ? 'border-purple-500 bg-purple-500/10' : 'border-zinc-700 hover:border-zinc-500'} 
          ${file ? 'bg-zinc-800/50' : 'bg-zinc-900/30'}
        `}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !file && fileInputRef.current?.click()}
        style={{ minHeight: "180px" }}
      >
        <input
          ref={fileInputRef}
          type="file"
          onChange={(e) => e.target.files && handleFileChange(e.target.files[0])}
          className="hidden"
          accept={acceptedFileTypes}
        />

        <div className="flex flex-col items-center justify-center p-6 text-center h-full">
          {!file && (
            <>
              <div className="w-16 h-16 bg-zinc-800 rounded-full flex items-center justify-center mb-4">
                <Upload className="w-8 h-8 text-zinc-400" />
              </div>
              <p className="text-lg font-medium text-white mb-1">{fileLabel}</p>
              <p className="text-sm text-zinc-400 mb-2">Drag & drop or click to browse</p>
              {acceptedFileTypes !== "*" && (
                <p className="text-xs text-zinc-500">Supported files: {acceptedFileTypes}</p>
              )}
            </>
          )}

          {file && !loading && (
            <div className="w-full">
              {/* File preview for images */}
              {preview && (
                <div className="mb-4 relative mx-auto" style={{ maxWidth: "200px" }}>
                  <img 
                    src={preview} 
                    alt="File preview" 
                    className="rounded-lg object-contain max-h-40 mx-auto border border-zinc-700"
                  />
                </div>
              )}
              
              <div className="flex items-center justify-between bg-zinc-800/50 rounded-lg p-3">
                <div className="flex items-center overflow-hidden">
                  <div className="w-10 h-10 bg-zinc-700 rounded-lg flex items-center justify-center flex-shrink-0 mr-3">
                    <FileText className="w-5 h-5 text-zinc-400" />
                  </div>
                  <div className="overflow-hidden">
                    <p className="text-sm text-white font-medium truncate">{file.name}</p>
                    <p className="text-xs text-zinc-400">{(file.size / 1024).toFixed(1)} KB</p>
                  </div>
                </div>
                <button 
                  onClick={(e) => {
                    e.stopPropagation();
                    clearFile();
                  }}
                  className="p-1.5 hover:bg-zinc-700 rounded-full transition-colors"
                  type="button"
                >
                  <X className="w-4 h-4 text-zinc-400" />
                </button>
              </div>
            </div>
          )}

          {loading && (
            <div className="flex flex-col items-center justify-center py-8">
              <Loader2 className="w-10 h-10 text-purple-500 animate-spin mb-4" />
              <p className="text-lg font-medium text-white">Scanning...</p>
              <p className="text-sm text-zinc-400">This may take a moment</p>
            </div>
          )}
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded-lg flex items-start">
          <AlertCircle className="w-5 h-5 text-red-400 mr-2 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Scan button */}
      <button
        onClick={handleSubmit}
        disabled={loading || !file}
        className={`
          w-full py-3 px-4 rounded-xl font-medium transition-all duration-300 flex items-center justify-center
          ${!file 
            ? 'bg-zinc-800 text-zinc-400 cursor-not-allowed' 
            : 'bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white'
          }
        `}
        type="button"
      >
        {loading ? (
          <>
            <Loader2 className="w-5 h-5 mr-2 animate-spin" />
            Scanning...
          </>
        ) : file ? (
          'Scan QR Code'
        ) : (
          'Select a File First'
        )}
      </button>

      {/* Results */}
      {result && !loading && (
        <div className="mt-6 bg-zinc-800/30 rounded-xl border border-zinc-700 overflow-hidden">
          <div className="bg-zinc-800 p-3 border-b border-zinc-700 flex items-center">
            <CheckCircle className="w-5 h-5 text-green-400 mr-2" />
            <h3 className="text-white font-medium">Scan Results</h3>
          </div>
          
          <div className="p-4">
            {result.url && (
              <div className="mb-4">
                <p className="text-sm text-zinc-400 mb-1">Detected URL:</p>
                <a 
                  href={result.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-sm bg-zinc-700/50 p-2 rounded border border-zinc-600 break-all block font-mono text-blue-400 hover:text-blue-300"
                >
                  {result.url}
                </a>
              </div>
            )}
            
            {result.text && (
              <div className="mb-4">
                <p className="text-sm text-zinc-400 mb-1">Extracted Text:</p>
                <div className="text-sm bg-zinc-700/50 p-2 rounded border border-zinc-600 break-words font-mono text-white">
                  {result.text}
                </div>
              </div>
            )}

            {!result.url && !result.text && (
              <pre className="text-sm overflow-x-auto bg-zinc-700/50 p-2 rounded border border-zinc-600 font-mono text-white">
                {JSON.stringify(result, null, 2)}
              </pre>
            )}
            
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => {
                  const textToCopy = result.url || result.text || JSON.stringify(result, null, 2);
                  navigator.clipboard.writeText(textToCopy);
                  alert("Copied to clipboard!"); // Ideally replace with a toast notification
                }}
                className="text-xs bg-zinc-700 hover:bg-zinc-600 text-zinc-200 px-3 py-1.5 rounded-md transition-colors"
                type="button"
              >
                Copy to Clipboard
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}