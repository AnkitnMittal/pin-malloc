import { Link, useLocation, Outlet } from 'react-router-dom';

export default function Layout() {
  const location = useLocation();
  const isDark = location.pathname === '/analyze';

  return (
    <div className={`min-h-screen ${isDark ? 'bg-[#020617] text-white' : 'bg-gray-50 text-gray-900'}`}>
      <nav className={`px-6 py-4 border-b ${isDark ? 'bg-[#081226] border-white/10' : 'bg-white border-gray-200 shadow-sm'}`}>
        <div className='max-w-350 mx-auto flex items-center justify-between'>
          <div className='font-bold text-lg tracking-tight'>
            Memory Trace<span className={isDark ? 'text-blue-500' : 'text-blue-600'}>.</span>
          </div>
          <div className='flex gap-6'>
            <Link to='/' className={`font-medium transition-colors hover:text-blue-500 ${!isDark && location.pathname === '/' ? 'text-blue-600' : ''}`}>
              Dashboard
            </Link>
            <Link
              to='/analyze'
              className={`font-medium transition-colors hover:text-blue-500 ${isDark && location.pathname === '/analyze' ? 'text-blue-400' : ''}`}
            >
              Analyze
            </Link>
          </div>
        </div>
      </nav>

      <Outlet />
    </div>
  );
}
