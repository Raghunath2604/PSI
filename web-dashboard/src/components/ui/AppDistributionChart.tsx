"use client"

import { FC } from "react"
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts"

interface AppData {
    name: string
    value: number
}

interface AppDistributionChartProps {
    data: AppData[]
}

const COLORS = [
    "#3b82f6", // blue
    "#ef4444", // red
    "#10b981", // green
    "#f59e0b", // yellow
    "#8b5cf6", // purple
    "#ec4899", // pink
    "#06b6d4", // cyan
    "#f97316", // orange
    "#64748b", // slate
]

export const AppDistributionChart: FC<AppDistributionChartProps> = ({ data }) => {
    if (data.length === 0) {
        return (
            <div className="h-[300px] flex items-center justify-center text-gray-500">
                No application data available
            </div>
        )
    }

    return (
        <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={2}
                        dataKey="value"
                        stroke="none"
                    >
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                    </Pie>
                    <Tooltip
                        formatter={(val: any) => [`${val} Packets`, 'Traffic']}
                        contentStyle={{ backgroundColor: "#1f2937", border: "none", borderRadius: "8px", color: "#fff" }}
                        itemStyle={{ color: "#fff" }}
                    />
                    <Legend
                        verticalAlign="bottom"
                        height={36}
                        wrapperStyle={{ fontSize: '12px', color: '#9ca3af' }}
                    />
                </PieChart>
            </ResponsiveContainer>
        </div>
    )
}
