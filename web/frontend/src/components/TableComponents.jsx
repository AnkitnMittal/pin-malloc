export function TH({ children }) {
  return <th className='text-left p-4 text-sm font-semibold text-gray-600 uppercase tracking-wider'>{children}</th>;
}

export function TD({ children, className = '' }) {
  return <td className={`p-4 text-sm text-gray-700 ${className}`}>{children}</td>;
}
