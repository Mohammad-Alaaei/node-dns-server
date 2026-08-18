/**
 * This will force app to go to next router.
 * 
 * Call this as last middleware in route to prevent
 * running next route in same router.
 * 
 * this is usefull when you are using middlewares in a
 * route that don't end response and use next() to go to
 * next route.
 */
export const nextRouter = async (req, res, next) => {
    return next('router');
}