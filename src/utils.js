function omit(obj, ...keys) {
  const result = { ...obj };
  keys.forEach(key => {
      delete result[key];
  });
  return result;
}


function omitFromArray(jsonArray, ...keys) {
  return jsonArray.map(obj => omit(obj, ...keys));
}

function formatStringToDate(dateString) {
  const date = new Date(dateString);
  const utcDate = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  return utcDate.toISOString();
}

function formatDateToString(date) {
  return date.toISOString().split('T')[0];
}

module.exports = {
  omit,
  omitFromArray,
  formatStringToDate,
  formatDateToString
};
