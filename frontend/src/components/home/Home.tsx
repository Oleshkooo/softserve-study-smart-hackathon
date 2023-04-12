import classes from './Home.module.css'
import { Link } from 'react-router-dom';

function Home() {
    return(
        <div className={classes.main}>
          <article className={classes.article}>
            <h1>Привіт, студенте!</h1>    
            <p>Вибери опцію, щоб продовжити</p>
          </article>
          <div className={classes.buttons}>
            <Link to={'/signin'}>Увійти</Link>
            <Link to={'/signup'}>Зареєструватись</Link>
          </div>
        </div>
    )
}

export default Home;