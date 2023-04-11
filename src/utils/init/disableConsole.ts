type DisableConsole = () => void

export const disableConsoleMessages: DisableConsole = () => {
    console.assert = () => {}
    console.clear = () => {}
    console.count = () => {}
    console.countReset = () => {}
    console.debug = () => {}
    console.dir = () => {}
    console.dirxml = () => {}
    console.error = () => {}
    console.group = () => {}
    console.groupCollapsed = () => {}
    console.groupEnd = () => {}
    console.info = () => {}
    console.log = () => {}
    console.profile = () => {}
    console.profileEnd = () => {}
    console.table = () => {}
    console.time = () => {}
    console.timeEnd = () => {}
    console.timeLog = () => {}
    console.timeStamp = () => {}
    console.trace = () => {}
    console.warn = () => {}
}

export const disableConsole: DisableConsole = () => {
    console.clear()
    disableConsoleMessages()
}
