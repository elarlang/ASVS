# V3 Gestión de sesiones

## Objetivo de Control

Uno de los componentes principales de cualquier aplicación basada en web o stateful API es el mecanismo por el cual controla y mantiene el estado de un usuario o dispositivo que interactúa con él. La gestión de sesiones cambia un protocolo sin estado (stateless) a uno con estado (stateful), lo que es fundamental para diferenciar diferentes usuarios o dispositivos.

Asegúrese de que una aplicación verificada cumple los siguientes requisitos de gestión de sesiones de alto nivel:

* Las sesiones son únicas para cada individuo y no se pueden adivinar ni compartir.
* Las sesiones se invalidan cuando ya no son necesarias y se agota el tiempo de espera durante los períodos de inactividad.

Como se ha señalado anteriormente, estos requisitos se han adaptado para ser un subconjunto compatible de controles NIST 800-63b seleccionados, centrados en amenazas comunes y debilidades de autenticación comúnmente explotadas. Los requisitos de verificación anteriores han sido retirados, eliminado redundancias, o en la mayoría de los casos, adaptados para estar fuertemente alineados con los requisitos obligatorios de [NIST 800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html).

## Requisitos de Verificación de Seguridad

## V3.1 Seguridad Fundamental en la Gestión de Sesiones

| # | Descripción | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **3.1.1** | Verifique que la aplicación nunca revela tokens de sesión en parámetros de dirección URL. | ✓ | ✓ | ✓ | 598 | |

## V3.2 Binding de Sesión

| # | Descripción | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **3.2.1** | Verifique que la aplicación genera un nuevo token de sesión en la autenticación de usuario. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 384 | 7.1 |
| **3.2.2** | Verifique que los tokens de sesión posean al menos 64 bits de entropía. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 331 | 7.1 |
| **3.2.3** | Verifique que la aplicación solo almacena tokens de sesión en el navegador mediante métodos seguros, como proteger las cookies adecuadamente (consulte la sección 3.4) o el almacenamiento de sesión en HTML 5. | ✓ | ✓ | ✓ | 539 | 7.1 |
| **3.2.4** | Verifique que los tokens de sesión se generan mediante algoritmos criptográficos aprobados. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | | ✓ | ✓ | 331 | 7.1 |

TLS u otro canal de transporte seguro es obligatorio para la gestión de sesiones. Esto se trata en el capítulo Seguridad de las comunicaciones.

## V3.3 Terminación de Sesión

Los tiempos de espera de sesión se han alineado con NIST 800-63, lo que permite tiempos de espera de sesión mucho más largos de lo permitido tradicionalmente por los estándares de seguridad. Las organizaciones deben revisar la tabla siguiente y, si es deseable un tiempo de espera más largo en función del riesgo de la aplicación, el valor NIST debe ser los límites superiores de los tiempos de espera de inactividad de sesión.

L1 en este contexto es IAL1/AAL1, L2 es IAL2/AAL3, L3 es IAL3/AAL3. Para IAL2/AAL2 e IAL3/AAL3, el tiempo de espera de inactividad más corto es, el límite inferior de los tiempos de inactividad para ser cerrado o re-autenticado para reanudar la sesión.

| # | Descripción | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **3.3.1** | Verifique que el cierre de sesión y la expiración invalidan el token de sesión, de modo que el botón "Atrás" o un usuario de confianza posterior no reanude una sesión autenticada, incluso entre los usuarios de confianza. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 613 | 7.1 |
| **3.3.2** | Si los autenticadores permiten a los usuarios permanecer conectados, compruebe que la re-autenticación se produce periódicamente tanto cuando se utiliza activamente o después de un período de inactividad. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | 30 días | 12 horas o 30 minutos de inactividad, 2FA opcional | 12 horas o 15 minutos de inactividad, con 2FA | 613 | 7.2 |
| **3.3.3** | Verifique que la aplicación ofrece la opción de terminar todas las demás sesiones activas después de un cambio de contraseña correcto (incluido el cambio mediante el restablecimiento/recuperación de contraseña), y que esto es efectivo en toda la aplicación, el inicio de sesión federado (si está presente) y cualquier usuario de confianza. | | ✓ | ✓ | 613 | |
| **3.3.4** | Verifique que los usuarios pueden ver y (habiendo vuelto a introducir las credenciales de inicio de sesión) cerrar sesión en cualquiera o todas las sesiones y dispositivos activos actualmente. | | ✓ | ✓ | 613 | 7.1 |

## V3.4 Gestión de Sesión Basada en Cookie

| # | Descripción | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **3.4.1** | Verifique que los tokens de sesión basados en cookies tengan el atributo 'Secure' establecido. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 614 | 7.1.1 |
| **3.4.2** | Verifique que los tokens de sesión basados en cookies tienen el atributo 'HttpOnly' establecido. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 1004 | 7.1.1 |
| **3.4.3** | Verifique que los tokens de sesión basados en cookies utilizan el atributo 'SameSite' para limitar la exposición a ataques de falsificación de solicitudes entre sitios. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 16 | 7.1.1 |
| **3.4.4** | Verifique que los tokens de sesión basados en cookies utilizan el prefijo "__Host-" para que las cookies solo se envíen al host que configuró inicialmente la cookie. | ✓ | ✓ | ✓ | 16 | 7.1.1 |
| **3.4.5** | Verifique que si la aplicación se publica bajo un nombre de dominio con otras aplicaciones que establecen o usan cookies de sesión que podrían revelar las cookies de sesión, establezca el atributo de ruta en tokens de sesión basados en cookies utilizando la ruta más precisa posible. ([C6](https://owasp.org/www-project-proactive-controls/#div-numbering)) | ✓ | ✓ | ✓ | 16 | 7.1.1 |

## V3.5 Administración de Sesiones Basada en Tokens

La gestión de sesiones basada en tokens incluye JWT, OAuth, SAML y API keys. De estos, se sabe que las API keys son débiles y no se deben usar en código nuevo.

| # | Descripción | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **3.5.1** | Verifique que la aplicación permite a los usuarios revocar tokens de OAuth que forman relaciones de confianza con aplicaciones vinculadas. | | ✓ | ✓ | 290 | 7.1.2 |
| **3.5.2** | Verifique que la aplicación utiliza tokens de sesión en lugar de claves y secretos de API estáticos, excepto con implementaciones heredadas. | | ✓ | ✓ | 798 | |
| **3.5.3** | Verifique que los tokens de sesión sin estado utilizan firmas digitales, cifrado y otras contramedidas para protegerse contra ataques de manipulación, envolvente, reproducción, cifrado nulo y sustitución de claves. | | ✓ | ✓ | 345 | |

## V3.6 Reautenticación Federada

Esta sección se relaciona con aquellos que escriben el código de Partes de confianza (RP) o proveedores de servicios de credenciales (CSP). Si confía en el código que implementa estas características, asegúrese de que estos problemas se manejen correctamente.

| # | Descripción | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **3.6.1** | Verifique que las partes de confianza (RP) especifiquen el tiempo máximo de autenticación para los proveedores de servicios de credenciales (CSP) y que los CSP vuelvan a autenticar al usuario si no han utilizado una sesión dentro de ese período. | | | ✓ | 613 | 7.2.1 |
| **3.6.2** | Verifique que los proveedores de servicios de credenciales (CSP) informan a las partes de confianza (RP) del último evento de autenticación, para permitir que los RP determinen si necesitan volver a autenticar al usuario. | | | ✓ | 613 | 7.2.1 |

## V3.7 Defensas Contra las Vulnerabilidades de Gestión de Sesiones

Hay un pequeño número de ataques de gestión de sesiones, algunos relacionados con la experiencia del usuario (UX) de las sesiones. Anteriormente, sobre la base de los requisitos ISO 27002, el ASVS ha requerido bloquear varias sesiones simultáneas. El bloqueo de sesiones simultáneas ya no es adecuado, no sólo porque los usuarios modernos tienen muchos dispositivos o la aplicación es una API sin una sesión de navegador, pero en la mayoría de estas implementaciones, el último autenticador gana, que a menudo es el atacante. En esta categoría se proporcionan instrucciones principales sobre cómo disuadir, retrasar y detectar ataques de gestión de sesiones mediante código.

### Descripción del Ataque semi-abierto

A principios de 2018, varias instituciones financieras se vieron comprometidas usando lo que los atacantes llamaron "ataques semi abiertos". Este término se ha atascado en la industria. Los atacantes golpearon múltiples instituciones con diferentes bases de código propietario, y de hecho parece diferentes bases de código dentro de las mismas instituciones. El ataque semi-abierto explota un defecto de patrón de diseño que se encuentra comúnmente en muchos sistemas existentes de autenticación, gestión de sesiones y control de acceso.

Los atacantes inician un ataque semi-abierto al intentar bloquear, restablecer o recuperar una credencial. Un patrón de diseño de gestión de sesiones popular reutiliza los objetos/modelos de sesión de perfil de usuario entre objetos/modelos no autenticados y autenticados a semi-autorizado (restablecimiento de contraseña, nombre de usuario olvidado) y código totalmente autenticado. Este patrón de diseño rellena un objeto de sesión o token válido que contiene el perfil de la víctima, incluidos los roles y hashes de contraseña. Si las comprobaciones de control de acceso en controladores o routers no comprueban correctamente que el usuario ha iniciado sesión por completo, el atacante podrá actuar como si fuera el usuario. Los ataques podrían incluir cambiar la contraseña del usuario a un valor conocido, actualizar la dirección de correo electrónico para realizar un restablecimiento de contraseña válido, deshabilitar la autenticación multifactor o inscribir un nuevo dispositivo MFA, revelar o cambiar claves de API, etc.

| # | Descripción | L1 | L2 | L3 | CWE | [NIST &sect;](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| :---: | :--- | :---: | :---:| :---: | :---: | :---: |
| **3.7.1** | Verifique que la aplicación garantiza una sesión de inicio de sesión completa y válida o requiere una re-autenticación o verificación secundaria antes de permitir cualquier transacción confidencial o modificaciones de la cuenta. | ✓ | ✓ | ✓ | 306 | |

## Referencias

Para obtener más información, véase también:

* [OWASP Testing Guide 4.0: Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/README.html)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [Set-Cookie __Host- prefix details](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives)
