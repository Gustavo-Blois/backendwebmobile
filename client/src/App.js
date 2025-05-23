import logo from './logo.svg';
import './App.css';

function App() {
  return (
    <div>
    <h1>LOGIN</h1>
    <form action="http://localhost:8080/login" method="post" class="form-example">
      <input type="text" name="user" id="user" required />
      <input type="text" name="password" id="password" required />
      <button>logar</button>
    </form>
    </div>
  );
}

export default App;
