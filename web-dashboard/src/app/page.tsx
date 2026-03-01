"use client"

import { useState, useCallback } from "react"
import { UploadCloud, ShieldAlert, Activity, ArrowDownUp, CheckCircle2, ShieldBan } from "lucide-react"
import { StatCard } from "@/components/ui/StatCard"
import { AppDistributionChart } from "@/components/ui/AppDistributionChart"
import { formatBytes, cn } from "@/lib/utils"

interface Flow {
  src_ip: string
  dst_ip: string
  dst_port: number
  app: string
  sni: string
  ja3?: string
  packets: number
  bytes: number
  blocked: boolean
}

interface ReportData {
  generated?: string
  total_packets?: number
  total_bytes?: number
  total_flows?: number
  dropped?: number
  flows: Flow[]
}

export default function Dashboard() {
  const [data, setData] = useState<ReportData | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const processFile = (file: File) => {
    if (!file.name.endsWith('.json')) {
      setError("Please upload a .json report file.")
      return
    }

    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target?.result as string) as ReportData
        if (!json.flows || !Array.isArray(json.flows)) {
          throw new Error("Invalid DPI report format. Missing 'flows' array.")
        }

        // Sort flows by bytes descending
        json.flows.sort((a, b) => b.bytes - a.bytes)

        // Calculate totals if missing from summary
        if (!json.total_packets) {
          json.total_packets = json.flows.reduce((sum, f) => sum + f.packets, 0)
        }
        if (!json.total_bytes) {
          json.total_bytes = json.flows.reduce((sum, f) => sum + f.bytes, 0)
        }
        if (!json.total_flows) {
          json.total_flows = json.flows.length
        }
        if (!json.dropped) {
          json.dropped = json.flows.filter(f => f.blocked).reduce((sum, f) => sum + f.packets, 0)
        }

        setData(json)
        setError(null)
      } catch (err: any) {
        setError("Failed to parse the report: " + err.message)
      }
    }
    reader.readAsText(file)
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const files = Array.from(e.dataTransfer.files)
    if (files.length > 0) processFile(files[0])
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files
    if (files && files.length > 0) processFile(files[0])
  }

  // Pre-process chart data
  const appMap = new Map<string, number>()
  if (data?.flows) {
    data.flows.forEach(f => {
      const app = f.app === "UNKNOWN" && f.sni ? "SNI: " + f.sni.substring(0, 10) : f.app;
      appMap.set(app, (appMap.get(app) || 0) + f.packets)
    })
  }
  const chartData = Array.from(appMap.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 8) // Top 8 apps

  // Render Upload Screen
  if (!data) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] text-gray-100 flex flex-col items-center justify-center p-6">
        <div className="max-w-xl w-full text-center space-y-8">
          <div className="space-y-4">
            <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-300">
              DPI Engine Dashboard
            </h1>
            <p className="text-gray-400 text-lg">
              Visualize your Deep Packet Inspection reports instantly.
            </p>
          </div>

          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={cn(
              "relative border-2 border-dashed rounded-2xl p-12 transition-all duration-300 ease-in-out group",
              isDragging
                ? "border-cyan-400 bg-cyan-400/10 scale-105"
                : "border-gray-700 bg-gray-800/30 hover:bg-gray-800/60 hover:border-gray-500"
            )}
          >
            <input
              type="file"
              accept=".json"
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              onChange={handleFileChange}
            />
            <div className="flex flex-col items-center space-y-4 pointer-events-none">
              <div className={cn(
                "p-4 rounded-full transition-colors duration-300",
                isDragging ? "bg-cyan-500/20 text-cyan-400" : "bg-gray-800 text-gray-400 group-hover:bg-gray-700 group-hover:text-blue-400"
              )}>
                <UploadCloud className="w-10 h-10" />
              </div>
              <div className="text-center">
                <p className="text-xl font-semibold mb-1 text-gray-200">
                  Drop <span className="text-cyan-400 font-mono">dpi_live_report.json</span> here
                </p>
                <p className="text-sm text-gray-500">or click to browse your files</p>
              </div>
            </div>
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-lg flex items-center justify-center space-x-2">
              <ShieldAlert className="w-5 h-5 flex-shrink-0" />
              <p>{error}</p>
            </div>
          )}
        </div>
      </div>
    )
  }

  // Render Dashboard
  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-4 md:p-8 font-sans selection:bg-cyan-500/30">

      {/* Header */}
      <div className="max-w-7xl mx-auto mb-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <span className="bg-blue-600 p-2 rounded-lg">
              <Activity className="w-6 h-6 text-white" />
            </span>
            <span>Network Analysis</span>
          </h1>
          <p className="text-gray-400 mt-2">
            Generated: <span className="text-gray-300">{data.generated || new Date().toLocaleString()}</span>
          </p>
        </div>
        <button
          onClick={() => setData(null)}
          className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm font-medium transition-colors"
        >
          Upload New Report
        </button>
      </div>

      <div className="max-w-7xl mx-auto space-y-8">

        {/* Top Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total Packets"
            value={data.total_packets?.toLocaleString() || 0}
            icon={ArrowDownUp}
            colorClass="bg-blue-500 text-blue-500"
          />
          <StatCard
            title="Total Bandwidth"
            value={formatBytes(data.total_bytes || 0)}
            icon={Activity}
            colorClass="bg-emerald-500 text-emerald-500"
          />
          <StatCard
            title="Active Flows"
            value={data.total_flows?.toLocaleString() || 0}
            icon={Activity}
            colorClass="bg-purple-500 text-purple-500"
          />
          <StatCard
            title="Blocked/Dropped"
            value={data.dropped?.toLocaleString() || 0}
            icon={ShieldBan}
            colorClass="bg-red-500 text-red-500"
          />
        </div>

        {/* Middle Section: Chart and Quick Info */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-xl lg:col-span-1 flex flex-col items-center justify-center">
            <h3 className="text-lg font-semibold text-white w-full text-center mb-6">Traffic Distribution</h3>
            <AppDistributionChart data={chartData} />
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl shadow-xl lg:col-span-2 overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-800">
              <h3 className="text-lg font-semibold text-white">Flow Details</h3>
              <p className="text-sm text-gray-400 mt-1">Sorted by bandwidth volume</p>
            </div>
            <div className="overflow-x-auto flex-1 h-[400px]">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-gray-800/50 text-gray-400 text-xs uppercase tracking-wider sticky top-0 backdrop-blur-md">
                    <th className="px-6 py-4 font-medium">Source IP</th>
                    <th className="px-6 py-4 font-medium">App / SNI</th>
                    <th className="px-6 py-4 font-medium">Destination</th>
                    <th className="px-6 py-4 font-medium text-right">Packets</th>
                    <th className="px-6 py-4 font-medium text-right">Bytes</th>
                    <th className="px-6 py-4 font-medium text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {data.flows.slice(0, 50).map((flow, idx) => (
                    <tr key={idx} className="hover:bg-gray-800/30 transition-colors group">
                      <td className="px-6 py-4 text-sm font-mono text-gray-300">
                        {flow.src_ip}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-col">
                          <span className={cn(
                            "font-semibold",
                            flow.app === 'YouTube' ? 'text-red-400' :
                              flow.app === 'TikTok' ? 'text-pink-400' :
                                flow.app === 'Google' ? 'text-blue-400' :
                                  flow.app === 'Discord' ? 'text-indigo-400' :
                                    'text-cyan-400'
                          )}>
                            {flow.app}
                          </span>
                          {flow.sni && <span className="text-xs text-gray-500 font-mono mt-0.5 truncate max-w-[200px]">{flow.sni}</span>}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400 font-mono">
                        {flow.dst_ip}<span className="text-gray-600">:{flow.dst_port}</span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300 text-right">
                        {flow.packets.toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300 text-right font-medium">
                        {formatBytes(flow.bytes)}
                      </td>
                      <td className="px-6 py-4 text-center">
                        {flow.blocked ? (
                          <div className="inline-flex items-center justify-center px-2 py-1 rounded bg-red-500/10 text-red-400 text-xs font-medium border border-red-500/20">
                            Blocked
                          </div>
                        ) : (
                          <div className="inline-flex items-center justify-center px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 text-xs font-medium border border-emerald-500/20">
                            Allowed
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                  {data.flows.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                        No flows recorded in this report.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {data.flows.length > 50 && (
              <div className="p-4 border-t border-gray-800 text-center text-sm text-gray-500 bg-gray-900/50">
                Showing top 50 flows (out of {data.flows.length})
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  )
}
