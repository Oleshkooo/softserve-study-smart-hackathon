import reactGA from 'react-ga'

import { GA_TRACKING_ID } from '@/config'

type GoogleAnalytics = () => void

export const googleAnalytics: GoogleAnalytics = () => {
    reactGA.initialize(GA_TRACKING_ID)
    reactGA.pageview(window.location.pathname + window.location.search)
}
