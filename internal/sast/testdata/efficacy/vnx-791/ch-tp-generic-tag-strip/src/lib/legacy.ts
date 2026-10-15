~>export const sanitizeOld = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
~>export const dropScripts = (s = "") => s.replaceAll("<script>", "")
