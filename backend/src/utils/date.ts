type GetDate = () => string

const locale = 'uk-UA'
const timeZone = 'Europe/Kiev'

export const getCurrentTimeString: GetDate = () =>
    new Date().toLocaleTimeString(locale, {
        timeZone,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    })

export const getCurrentDateString: GetDate = () =>
    new Date().toLocaleDateString(locale, {
        timeZone,
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
    })
