# Huellas de Plan B

Lista pública de huellas (sha256) de lo que el Panel Plan B puede instalar en las webs de los clientes:

- cada versión del **conector** (archivo a archivo, sin las claves de alta, que cambian en cada descarga);
- los **paquetes oficiales de los plugins y temas de Envato**, descargados aquí directamente de Envato.

La calcula sola una tarea de GitHub (`.github/workflows/huellas.yml`): al subir un conector nuevo y cada 3 horas.
Cada web, antes de instalar algo que le manda el panel, comprueba que su huella está en `huellas.json`.
Si alguien tocara el servidor del panel, lo que preparase allí no estaría en esta lista y las webs no lo instalarían.

Aquí no hay nada secreto. El token de Envato solo está en los *secrets* del repositorio.
