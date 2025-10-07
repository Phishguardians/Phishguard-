'use client'

import { useState, useEffect } from 'react'
import ScannerForm from "../../components/ScannerForm"
import { QrCode, Shield, ArrowRight, ScanLine, Info } from 'lucide-react'

export default function QRScanPage() {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 })
  const [mounted, setMounted] = useState(false)
  
  // Mouse position effect for background gradient
  useEffect(() => {
    setMounted(true)
    
    const handleMouseMove = (e: MouseEvent) => {
      setMousePosition({
        x: (e.clientX / window.innerWidth) * 100,
        y: (e.clientY / window.innerHeight) * 100,
      })
    }
    
    window.addEventListener('mousemove', handleMouseMove)
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [])

  if (!mounted) return null

  return (
    <div className="min-h-screen bg-black text-white overflow-hidden relative">
      {/* Dynamic Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div 
          className="absolute w-96 h-96 bg-purple-400/8 rounded-full blur-3xl transition-all duration-1000 ease-out"
          style={{
            top: `${mousePosition.y}%`,
            left: `${mousePosition.x}%`,
            transform: 'translate(-50%, -50%)',
          }}
        ></div>
        <div className="absolute top-1/4 left-1/4 w-80 h-80 bg-blue-400/6 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-72 h-72 bg-purple-400/6 rounded-full blur-3xl animate-pulse delay-1000"></div>
        
        {/* Cyber Grid Pattern */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(6,182,212,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(6,182,212,0.05)_1px,transparent_1px)] bg-[size:60px_60px] opacity-30"></div>
      </div>

      <div className="relative z-10 container mx-auto px-4 sm:px-6 py-12 sm:py-16">
        <div className="max-w-4xl mx-auto">
          
          {/* Header Section */}
          <div className="text-center mb-10">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-r from-violet-500 to-purple-600 rounded-2xl mb-6 shadow-lg shadow-purple-500/30">
              <QrCode className="w-10 h-10 text-white" />
            </div>
            
            <h1 className="text-4xl sm:text-5xl font-extrabold text-white mb-4 tracking-tight">
              <span className="bg-gradient-to-r from-violet-400 to-purple-500 bg-clip-text text-transparent">
                QR Code Scanner
              </span>
            </h1>
            
            <p className="text-lg text-gray-300 max-w-2xl mx-auto leading-relaxed">
              Upload QR code images to decode and extract their content
            </p>
          </div>

          {/* Main Content */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Scanner Form */}
            <div className="lg:col-span-2 bg-zinc-800/30 backdrop-blur-sm rounded-2xl border border-zinc-700/50 p-6 sm:p-8 shadow-xl">
              <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                <ScanLine className="w-5 h-5 text-purple-400" />
                Decode QR Code
              </h2>
              
              <ScannerForm 
                endpoint="http://localhost:8000/scan/qr/api/qr/scan" 
                fileLabel="Upload QR Code Image"
                acceptedFileTypes=".png,.jpg,.jpeg"
              />
            </div>

            {/* Info Sidebar */}
            <div className="space-y-6">
              {/* How It Works */}
              <div className="bg-zinc-800/30 backdrop-blur-sm rounded-2xl border border-zinc-700/50 p-6 shadow-xl">
                <h3 className="text-lg font-semibold text-white mb-4">How It Works</h3>
                <ul className="space-y-4">
                  <li className="flex gap-3">
                    <div className="w-6 h-6 bg-purple-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                      <span className="text-sm font-medium text-purple-400">1</span>
                    </div>
                    <p className="text-sm text-gray-300">Upload an image containing a QR code</p>
                  </li>
                  <li className="flex gap-3">
                    <div className="w-6 h-6 bg-purple-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                      <span className="text-sm font-medium text-purple-400">2</span>
                    </div>
                    <p className="text-sm text-gray-300">Our system extracts the QR code content</p>
                  </li>
                  <li className="flex gap-3">
                    <div className="w-6 h-6 bg-purple-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                      <span className="text-sm font-medium text-purple-400">3</span>
                    </div>
                    <p className="text-sm text-gray-300">View the extracted URL or text content</p>
                  </li>
                </ul>
              </div>
              
              {/* Features */}
              <div className="bg-purple-500/10 backdrop-blur-sm rounded-2xl border border-purple-500/20 p-6 shadow-xl">
                <h3 className="text-lg font-semibold text-white mb-4">Features</h3>
                <ul className="space-y-3">
                  <li className="flex items-start gap-2">
                    <div className="w-1.5 h-1.5 bg-purple-400 rounded-full mt-1.5"></div>
                    <span className="text-sm text-gray-300">QR code detection and parsing</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <div className="w-1.5 h-1.5 bg-purple-400 rounded-full mt-1.5"></div>
                    <span className="text-sm text-gray-300">URL extraction from QR codes</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <div className="w-1.5 h-1.5 bg-purple-400 rounded-full mt-1.5"></div>
                    <span className="text-sm text-gray-300">Text content extraction</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <div className="w-1.5 h-1.5 bg-purple-400 rounded-full mt-1.5"></div>
                    <span className="text-sm text-gray-300">JPG and PNG image support</span>
                  </li>
                </ul>
              </div>
              
              {/* Other Tools */}
              <div className="bg-zinc-800/30 backdrop-blur-sm rounded-2xl border border-zinc-700/50 p-6 shadow-xl">
                <h3 className="text-lg font-semibold text-white mb-4">Other Security Tools</h3>
                
                <div className="space-y-2">
                  <a 
                    href="/doc" 
                    className="flex items-center justify-between p-3 rounded-xl bg-zinc-700/30 hover:bg-zinc-700/50 transition-colors group"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
                        <Shield className="w-4 h-4 text-blue-400" />
                      </div>
                      <span className="text-sm text-gray-300 group-hover:text-white transition-colors">Document Scanner</span>
                    </div>
                    <ArrowRight className="w-4 h-4 text-gray-400 group-hover:text-white transition-colors" />
                  </a>
                  
                  <a 
                    href="/email" 
                    className="flex items-center justify-between p-3 rounded-xl bg-zinc-700/30 hover:bg-zinc-700/50 transition-colors group"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-green-500/20 rounded-lg flex items-center justify-center">
                        <Shield className="w-4 h-4 text-green-400" />
                      </div>
                      <span className="text-sm text-gray-300 group-hover:text-white transition-colors">Email Scanner</span>
                    </div>
                    <ArrowRight className="w-4 h-4 text-gray-400 group-hover:text-white transition-colors" />
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}