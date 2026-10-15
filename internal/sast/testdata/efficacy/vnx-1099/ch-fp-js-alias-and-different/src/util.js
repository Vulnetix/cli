function formatName(user) {
  return `${user.first} ${user.last}`;
}

const format_name_v2 = (user) => `${user.last}, ${user.first}`;

function to_html(s) {
  return s.replace(/&/g, "&amp;");
}

function toHtmlString(s) {
  return "<p>" + s + "</p>";
}

const getUserName = function (u) {
  return u.name;
};

const get_user_name = getUserName;
