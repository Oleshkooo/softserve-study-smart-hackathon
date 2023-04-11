import App from '@/App'
import { disableConsole, googleAnalytics } from '@/utils'
import { disableReactDevTools } from '@fvilers/disable-react-devtools'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

// ? global styles
// import '@/styles/globals.scss'

// ? font awesome
import('@/assets/icons/fontAwesome/all.min.css')
import('@/assets/icons/fontAwesome/svg-with-js.min.css')

const container = document.getElementById('root') as HTMLElement
const root = createRoot(container)

root.render(
    <StrictMode>
        <BrowserRouter>
            <App />
        </BrowserRouter>
    </StrictMode>,
)

if (import.meta.env.NODE_ENV === 'production') {
    googleAnalytics()
    disableReactDevTools()
    disableConsole()
}
