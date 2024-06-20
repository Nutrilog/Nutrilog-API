const {
    postPredict,
    postRegister,
    loginUser,
    fetchNutrients,
    getFoodNutrientsByName
} = require('./handler');


const routes = [
    {
        method: 'POST',
        path: '/register',
        handler: postRegister,
    },
    {
        method: 'POST',
        path: '/login',
        handler: loginUser,
    },
    {
        method: 'POST',
        path: '/analyze',
        handler: postPredict,
    },
    {
        method: 'GET',
        path: '/nutrients',
        handler: fetchNutrients,
    },
    {
        method: 'POST',
        path: '/details',
        handler: getFoodNutrientsByName,
    },
    {
        method: '*',
        path: '/{any*}',
        handler: (request, h) => {
            return "Halaman belum dibuat";
        },
    },
];

module.exports = routes;