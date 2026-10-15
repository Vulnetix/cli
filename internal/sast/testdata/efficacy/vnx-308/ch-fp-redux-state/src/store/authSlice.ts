import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  user: null,
  mfaRequired: false,
  loading: false,
};

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    loginSucceeded(state, action) {
      state.user = action.payload.user;
      state.mfaRequired = false;
    },
  },
});

export function resetLogin(dispatch) {
  dispatch(authSlice.actions.setMfaRequired(false));
}

export default authSlice.reducer;
