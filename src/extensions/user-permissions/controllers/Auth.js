
'use strict';


const _ = require('lodash');
// @ts-ignore
const { sanitizeEntity } = require('strapi-utils');

const emailRegExp = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

module.exports = {
  async register(ctx) {
    const pluginStore = await strapi.store({
      environment: '',
      type: 'plugin',
      name: 'users-permissions',
    });

    const settings = await pluginStore.get({
      key: 'advanced',
    });

    if (!settings.allow_register) {
      return ctx.badRequest(
        null,
        ctx.request.admin
          ? [{ messages: [{ id: 'Auth.advanced.allow_register' }] }]
          : 'Registrazione disabilitata.'
      );
    }

    const params = {
      // @ts-ignore
      ..._.omit(ctx.request.body, ['confirmed', 'confirmationToken', 'resetPasswordToken']),
      provider: 'local',
    };

    // Verifica email
    if (!emailRegExp.test(params.email)) {
      return ctx.badRequest('Per favore fornisci un indirizzo email valido.');
    }

    // Verifica password
    if (params.password.length < 6) {
      return ctx.badRequest('La password deve essere di almeno 6 caratteri.');
    }

    // Verifica username (può essere l'email)
    if (!params.username) {
      params.username = params.email;
    }

    // Scegli il ruolo in base al tipo di utente
    const roleType = params.role || 'candidato';
    const advanced = await pluginStore.get({
      key: 'advanced',
    });

    // Trova il ruolo (candidato o azienda)
    const roles = await strapi.query('plugin::users-permissions.role').findMany();
    const role = roles.find(r => r.type.toLowerCase() === roleType.toLowerCase());

    if (!role) {
      return ctx.badRequest(`Impossibile trovare il ruolo: ${roleType}`);
    }

    params.role = role.id;
    params.userType = roleType; // Salva il tipo di utente

    // Verifica se l'utente esiste già
    let user = await strapi.query('plugin::users-permissions.user').findOne({
      where: { username: params.username }
    });

    if (user) {
      return ctx.badRequest('Username/Email già in uso.');
    }

    // Crea l'utente
    try {
      const user = await strapi.query('plugin::users-permissions.user').create({ data: params });
      
      // Genera JWT token
      const jwt = strapi.plugins['users-permissions'].services.jwt.issue({
        id: user.id,
      });

      return {
        jwt,
        user: sanitizeEntity(user, {
          model: strapi.plugins['users-permissions'].models.user,
        }),
      };
    } catch (err) {
      return ctx.badRequest(err.toString());
    }
  }
};