const Hapi = require('@hapi/hapi');
const routes = require('./routes');

const init = async () => {
    const server = Hapi.server({
        port: 5000, //change to parseInt(process.env.port) || 8080 to deploy with cloud run
        host: 'localhost', //change to 0.0.0.0 to deploy 
        routes: {
            cors: {
                origin: ['*'],
            },
        },
    });

    
    server.route(routes)

    await server.start();
    console.log(`Server berjalan pada ${server.info.uri}`);
};

init();