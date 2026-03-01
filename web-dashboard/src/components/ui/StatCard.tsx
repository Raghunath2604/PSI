import { FC } from "react"
import { LucideIcon } from "lucide-react"

interface StatCardProps {
    title: string
    value: string | number
    icon: LucideIcon
    colorClass: string
}

export const StatCard: FC<StatCardProps> = ({ title, value, icon: Icon, colorClass }) => {
    return (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex items-start justify-between shadow-xl">
            <div>
                <p className="text-gray-400 text-sm font-medium mb-1">{title}</p>
                <h3 className="text-3xl font-bold text-white tracking-tight">{value}</h3>
            </div>
            <div className={`p-3 rounded-lg ${colorClass} bg-opacity-10`}>
                <Icon className={`w-6 h-6 ${colorClass.replace("bg-", "text-")}`} />
            </div>
        </div>
    )
}
